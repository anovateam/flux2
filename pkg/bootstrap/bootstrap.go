/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fluxcd/go-git-providers/gitprovider"
	"github.com/fluxcd/go-git-providers/validation"
	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	corev1 "k8s.io/api/core/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kustomize/api/filesys"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/flux2/internal/utils"
	"github.com/fluxcd/flux2/pkg/bootstrap/git"
	"github.com/fluxcd/flux2/pkg/log"
	"github.com/fluxcd/flux2/pkg/manifestgen/install"
	"github.com/fluxcd/flux2/pkg/manifestgen/kustomization"
	"github.com/fluxcd/flux2/pkg/manifestgen/sourcesecret"
	"github.com/fluxcd/flux2/pkg/manifestgen/sync"
)

type Bootstrap struct {
	git          git.Git
	provider     gitprovider.Client
	kube         client.Client
	log          log.Logger
	pollInterval time.Duration
	timeout      time.Duration
	kubeConfig   string
	kubeContext  string
}

// RemoteRepositoryRef is a simple struct with information about a
// remote repository.
type RemoteRepositoryRef struct {
	gitprovider.UserRef
	URL string
}

// String returns the HTTPS URL to access the repository.
func (r RemoteRepositoryRef) String() string {
	return r.URL
}

// GetRepository returns the repository name for this repo.
func (r RemoteRepositoryRef) GetRepository() string {
	return r.URL
}

// ValidateFields validates its own fields for a given validator.
func (r RemoteRepositoryRef) ValidateFields(validator validation.Validator) {}

// GetCloneURL gets the clone URL for the specified transport type.
func (r RemoteRepositoryRef) GetCloneURL(_ gitprovider.TransportType) string {
	return r.URL
}

func NewBootstrap(git git.Git, provider gitprovider.Client, log log.Logger, pollInterval, timeout time.Duration,
	kubeConfig, kubeContext string) (*Bootstrap, error) {

	kube, err := utils.KubeClient(kubeConfig, kubeContext)
	if err != nil {
		return nil, err
	}
	return &Bootstrap{
		git:          git,
		provider:     provider,
		log:          log,
		kube:         kube,
		pollInterval: pollInterval,
		timeout:      timeout,
		kubeConfig:   kubeConfig,
		kubeContext:  kubeContext,
	}, nil
}

var ErrFailedWithWarning = errors.New("failed with warning")

func (b *Bootstrap) Reconcile(ctx context.Context, manifestsBase string, installOpts install.Options, secretOpts sourcesecret.Options,
	syncOpts sync.Options, repo gitprovider.RepositoryRef, repoInfo *gitprovider.RepositoryInfo, accessInfo ...gitprovider.TeamAccessInfo) error {

	var r gitprovider.UserRepository
	switch repo.(type) {
	case gitprovider.OrgRepositoryRef:
		var err error
		if r, err = b.OrgRepository(ctx, repo.(gitprovider.OrgRepositoryRef), *repoInfo, accessInfo...); err != nil {
			return err
		}
	case gitprovider.UserRepositoryRef:
		var err error
		if r, err = b.UserRepository(ctx, repo.(gitprovider.UserRepositoryRef), *repoInfo); err != nil {
			return err
		}
	}

	if err := b.ComponentConfig(ctx, manifestsBase, repo.GetCloneURL(gitprovider.TransportTypeHTTPS), syncOpts.Branch, installOpts); err != nil {
		return err
	}

	if err := b.SourceSecret(ctx, r, secretOpts); err != nil {
		return err
	}

	if err := b.SyncConfig(ctx, repo.GetCloneURL(gitprovider.TransportTypeHTTPS), syncOpts.Branch, syncOpts); err != nil {
		return err
	}

	return nil
}

func (b *Bootstrap) OrgRepository(ctx context.Context, ref gitprovider.OrgRepositoryRef, info gitprovider.RepositoryInfo,
	accessInfo ...gitprovider.TeamAccessInfo) (gitprovider.UserRepository, error) {

	// Reconcile repository config
	b.log.Actionf("connecting to %s", ref.Domain)
	r, changed, err := b.provider.OrgRepositories().Reconcile(ctx, ref, info)
	if err != nil {
		return nil, err
	}
	if changed {
		b.log.Successf("repository %s reconciled", ref.String())
	}

	// Reconcile repository permission config on best effort
	var warning error
	if count := len(accessInfo); count > 0 {
		b.log.Actionf("reconciling %d permission rules", count)
		for _, i := range accessInfo {
			var err error
			_, changed, err = r.TeamAccess().Reconcile(ctx, i)
			if err != nil {
				warning = ErrFailedWithWarning
				b.log.Failuref("failed to grant %s permissions to %s: %w", i.Permission, i.Name, err)
			}
			if changed {
				b.log.Successf("granted %s permissions to %s", i.Permission, i.Name)
			}
		}
	}
	return r, warning
}

func (b *Bootstrap) UserRepository(ctx context.Context, ref gitprovider.UserRepositoryRef,
	info gitprovider.RepositoryInfo) (gitprovider.UserRepository, error) {

	// Reconcile repository config
	b.log.Actionf("connecting to %s", ref.Domain)
	r, changed, err := b.provider.UserRepositories().Reconcile(ctx, ref, info)
	if err != nil {
		return nil, err
	}
	if changed {
		b.log.Successf("repository %s reconciled", ref.String())
	}
	return r, nil
}

func (b *Bootstrap) SourceSecret(ctx context.Context, repo gitprovider.UserRepository,
	options sourcesecret.Options) error {

	// Determine if there is an existing secret
	secretKey := client.ObjectKey{Name: options.Name, Namespace: options.Namespace}
	b.log.Actionf("determining if source secret %s exists", secretKey)
	ok, err := b.secretExists(ctx, secretKey)
	if err != nil {
		return fmt.Errorf("failed to determine if deploy key secret exists: %w", err)
	}
	// Return early if exists and no custom config is passed
	if ok && len(options.CAFilePath+options.PrivateKeyPath+options.Username+options.Password) == 0 {
		b.log.Successf("source secret up to date")
		return nil
	}

	// Generate source secret
	b.log.Actionf("generating source secret")
	manifest, err := sourcesecret.Generate(options)
	if err != nil {
		return err
	}

	var secret corev1.Secret
	if err := yaml.Unmarshal([]byte(manifest.Content), &secret); err != nil {
		return fmt.Errorf("failed to unmarshal generated source secret manifest: %w", err)
	}

	// Upsert public key
	ppk, ok := secret.StringData[sourcesecret.PublicKeySecretKey]
	if ok {
		if repo != nil {
			b.log.Actionf("reconciling deploy key configuration for %s", repo.Repository().GetRepository())
			keyInfo := gitprovider.DeployKeyInfo{
				Name: options.Name,
				Key:  []byte(ppk),
			}
			_, changed, err := repo.DeployKeys().Reconcile(ctx, keyInfo)
			if err != nil {
				return err
			}
			if changed {
				b.log.Successf("updated deploy key configuration")
			} else {
				b.log.Successf("deploy key configuration is up to date")
			}
		}
		b.log.Successf("public key: %s", strings.TrimSpace(ppk))
	}

	// Apply source secret
	b.log.Actionf("applying source secret %s", secret.Name)
	if err = b.reconcileSecret(ctx, secret); err != nil {
		return err
	}

	b.log.Successf("reconciled source secret")
	return nil
}

func (b *Bootstrap) ComponentConfig(ctx context.Context, manifestsBase, url, branch string, options install.Options) error {

	// Clone if not already
	if _, err := b.git.Status(); err != nil {
		if err != git.ErrNoGitRepository {
			return err
		}

		b.log.Actionf("cloning Git repository from %s", url)
		cloned, err := b.git.Clone(ctx, url, branch)
		if err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
		if cloned {
			b.log.Successf("cloned repository")
		}
	}

	// Generate component manifests
	b.log.Actionf("generating component manifests")
	manifests, err := install.Generate(options, manifestsBase)
	if err != nil {
		return fmt.Errorf("component manifest generation failed: %w", err)
	}
	b.log.Successf("generated component manifests")

	// Write manifest to Git repository
	if err = b.git.Write(manifests.Path, strings.NewReader(manifests.Content)); err != nil {
		return fmt.Errorf("failed to write manifest %s: %w", manifests.Path, err)
	}

	// Git commit generated
	head, err := b.git.Commit(git.Commit{
		Author:  git.Author{Name: "Flux", Email: "bot@fluxcd.io"},
		Message: fmt.Sprintf("Add Flux component manifests"),
	})
	if err != nil && err != git.ErrNoStagedFiles {
		return fmt.Errorf("failed to commit sync manifests: %w", err)
	}
	if err == nil {
		b.log.Successf("committed component manifests in %s (%s)", branch, head)
		b.log.Actionf("pushing component manifests to %s", url)
		if err = b.git.Push(ctx); err != nil {
			return fmt.Errorf("failed to push manifests: %w", err)
		}
	} else {
		b.log.Successf("component manifests are up to date")
	}

	// Confirm running, apply to cluster if not
	healthy, err := b.Healthy(ctx)
	if err != nil {
		return err
	}
	if !healthy {
		b.log.Actionf("installing components in %s namespace", options.Namespace)
		kubectlArgs := []string{"apply", "-f", filepath.Join(b.git.Path(), manifests.Path)}
		if _, err = utils.ExecKubectlCommand(ctx, utils.ModeStderrOS, b.kubeConfig, b.kubeContext, kubectlArgs...); err != nil {
			return err
		}
	}

	b.log.Successf("reconciled components")
	return nil
}

func (b *Bootstrap) SyncConfig(ctx context.Context, url, branch string, options sync.Options) error {

	// Clone if not already
	if _, err := b.git.Status(); err != nil {
		if err == git.ErrNoGitRepository {
			b.log.Actionf("cloning Git repository from %s", url)
			cloned, err := b.git.Clone(ctx, url, branch)
			if err != nil {
				return fmt.Errorf("failed to clone repository: %w", err)
			}
			if cloned {
				b.log.Successf("cloned repository", url)
			}
		}
		return err
	}

	// Generate sync manifests and write to Git repository
	b.log.Actionf("generating sync manifests")
	manifests, err := sync.Generate(options)
	if err != nil {
		return fmt.Errorf("sync manifests generation failed: %w", err)
	}
	if err = b.git.Write(manifests.Path, strings.NewReader(manifests.Content)); err != nil {
		return fmt.Errorf("failed to write manifest %s: %w", manifests.Path, err)
	}
	kusManifests, err := kustomization.Generate(kustomization.Options{
		FileSystem: filesys.MakeFsOnDisk(),
		BaseDir:    b.git.Path(),
		TargetPath: filepath.Dir(manifests.Path),
	})
	if err != nil {
		return fmt.Errorf("kustomization.yaml generation failed: %w", err)
	}
	if err = b.git.Write(kusManifests.Path, strings.NewReader(kusManifests.Content)); err != nil {
		return fmt.Errorf("failed to write manifest %s: %w", kusManifests.Path, err)
	}
	b.log.Successf("generated sync manifests")

	// Git commit generated
	commit, err := b.git.Commit(git.Commit{
		Author: git.Author{
			Name:  "Flux",
			Email: "bot@fluxcd.io",
		},
		Message: fmt.Sprintf("Add Flux sync manifests"),
	})
	if err != nil && err != git.ErrNoStagedFiles {
		return fmt.Errorf("failed to commit sync manifests: %w", err)
	}
	if err == nil {
		b.log.Successf("committed sync manifests in %s (%s)", options.Branch, commit)
		b.log.Actionf("pushing sync manifests to %s", url)
		if err = b.git.Push(ctx); err != nil {
			return fmt.Errorf("failed to push sync manifests: %w", err)
		}
	} else {
		b.log.Successf("sync manifests are up to date")
	}

	// Apply to cluster
	b.log.Actionf("applying sync manifests")
	kubectlArgs := []string{"apply", "-k", filepath.Join(b.git.Path(), filepath.Dir(kusManifests.Path))}
	if _, err = utils.ExecKubectlCommand(ctx, utils.ModeStderrOS, b.kubeConfig, b.kubeContext, kubectlArgs...); err != nil {
		return err
	}
	b.log.Successf("applied sync manifests")

	// Wait till Kustomization is reconciled
	var k kustomizev1.Kustomization
	if err := wait.PollImmediate(b.pollInterval, b.timeout,
		b.kustomizationReconciled(ctx, client.ObjectKey{Name: options.Name, Namespace: options.Namespace}, &k, options.Branch, commit)); err != nil {
		return fmt.Errorf("failed waiting for Kustomization: %w", err)
	}

	b.log.Successf("reconciled sync configuration")
	return nil
}

func (b *Bootstrap) Healthy(ctx context.Context) (bool, error) {
	// TODO(hidde): implement check using kstatus, best option is probably
	//  to move `cmd/status.go` to a package and make it a bit more generic.
	return false, nil
}

func (b *Bootstrap) secretExists(ctx context.Context, objKey client.ObjectKey) (bool, error) {
	if err := b.kube.Get(ctx, objKey, &corev1.Secret{}); err != nil {
		if apierr.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *Bootstrap) reconcileSecret(ctx context.Context, secret corev1.Secret) error {
	objKey := client.ObjectKeyFromObject(&secret)
	var existing corev1.Secret
	err := b.kube.Get(ctx, objKey, &existing)
	if err != nil {
		if apierr.IsNotFound(err) {
			if err := b.kube.Create(ctx, &secret); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	existing.StringData = secret.StringData
	return b.kube.Update(ctx, &existing)
}

func (b *Bootstrap) kustomizationReconciled(ctx context.Context,
	objKey client.ObjectKey, kustomization *kustomizev1.Kustomization, branch, revision string) func() (bool, error) {

	return func() (bool, error) {
		if err := b.kube.Get(ctx, objKey, kustomization); err != nil {
			return false, err
		}

		// Confirm the state we are observing is for the current generation
		if kustomization.Generation != kustomization.Status.ObservedGeneration {
			return false, nil
		}

		// Confirm the given revision has been attempted by the controller
		if kustomization.Status.LastAttemptedRevision != fmt.Sprintf("%s/%s", branch, revision) {
			return false, nil
		}

		// Confirm the resource is healthy
		if c := apimeta.FindStatusCondition(kustomization.Status.Conditions, meta.ReadyCondition); c != nil {
			switch c.Status {
			case metav1.ConditionTrue:
				return true, nil
			case metav1.ConditionFalse:
				return false, fmt.Errorf(c.Message)
			}
		}
		return false, nil
	}
}
