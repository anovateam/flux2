/*
Copyright 2020 The Flux authors

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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/fluxcd/go-git-providers/github"
	"github.com/fluxcd/go-git-providers/gitprovider"
	"github.com/fluxcd/pkg/git"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/spf13/cobra"

	"github.com/fluxcd/flux2/internal/flags"
	"github.com/fluxcd/flux2/internal/utils"
	"github.com/fluxcd/flux2/pkg/bootstrap"
	"github.com/fluxcd/flux2/pkg/bootstrap/git/gogit"
	"github.com/fluxcd/flux2/pkg/manifestgen/install"
	"github.com/fluxcd/flux2/pkg/manifestgen/sourcesecret"
	"github.com/fluxcd/flux2/pkg/manifestgen/sync"
)

var bootstrapGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Bootstrap toolkit components in a GitHub repository",
	Long: `The bootstrap github command creates the GitHub repository if it doesn't exists and
commits the toolkit components manifests to the main branch.
Then it configures the target cluster to synchronize with the repository.
If the toolkit components are present on the cluster,
the bootstrap command will perform an upgrade if needed.`,
	Example: `  # Create a GitHub personal access token and export it as an env var
  export GITHUB_TOKEN=<my-token>

  # Run bootstrap for a private repo owned by a GitHub organization
  flux bootstrap github --owner=<organization> --repository=<repo name>

  # Run bootstrap for a private repo and assign organization teams to it
  flux bootstrap github --owner=<organization> --repository=<repo name> --team=<team1 slug> --team=<team2 slug>

  # Run bootstrap for a repository path
  flux bootstrap github --owner=<organization> --repository=<repo name> --path=dev-cluster

  # Run bootstrap for a public repository on a personal account
  flux bootstrap github --owner=<user> --repository=<repo name> --private=false --personal=true

  # Run bootstrap for a private repo hosted on GitHub Enterprise using SSH auth
  flux bootstrap github --owner=<organization> --repository=<repo name> --hostname=<domain> --ssh-hostname=<domain>

  # Run bootstrap for a private repo hosted on GitHub Enterprise using HTTPS auth
  flux bootstrap github --owner=<organization> --repository=<repo name> --hostname=<domain> --token-auth

  # Run bootstrap for a an existing repository with a branch named main
  flux bootstrap github --owner=<organization> --repository=<repo name> --branch=main
`,
	RunE: bootstrapGitHubCmdRun,
}

type githubFlags struct {
	owner       string
	repository  string
	interval    time.Duration
	personal    bool
	private     bool
	hostname    string
	path        flags.SafeRelativePath
	teams       []string
	sshHostname string
}

const (
	ghDefaultPermission = "maintain"
)

var githubArgs githubFlags

func init() {
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.owner, "owner", "", "GitHub user or organization name")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.repository, "repository", "", "GitHub repository name")
	bootstrapGitHubCmd.Flags().StringArrayVar(&githubArgs.teams, "team", []string{}, "GitHub team to be given maintainer access")
	bootstrapGitHubCmd.Flags().BoolVar(&githubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	bootstrapGitHubCmd.Flags().BoolVar(&githubArgs.private, "private", true, "if true, the repository is assumed to be private")
	bootstrapGitHubCmd.Flags().DurationVar(&githubArgs.interval, "interval", time.Minute, "sync interval")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.hostname, "hostname", git.GitHubDefaultHostname, "GitHub hostname")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.sshHostname, "ssh-hostname", "", "GitHub SSH hostname, to be used when the SSH host differs from the HTTPS one")
	bootstrapGitHubCmd.Flags().Var(&githubArgs.path, "path", "path relative to the repository root, when specified the cluster sync will be scoped to this path")

	bootstrapCmd.AddCommand(bootstrapGitHubCmd)
}

func bootstrapGitHubCmdRun(cmd *cobra.Command, args []string) error {
	ghToken := os.Getenv(git.GitHubTokenName)
	if ghToken == "" {
		return fmt.Errorf("%s environment variable not found", git.GitHubTokenName)
	}

	if err := bootstrapValidate(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	kubeClient, err := utils.KubeClient(rootArgs.kubeconfig, rootArgs.kubecontext)
	if err != nil {
		return err
	}

	usedPath, bootstrapPathDiffers := checkIfBootstrapPathDiffers(
		ctx,
		kubeClient,
		rootArgs.namespace,
		filepath.ToSlash(githubArgs.path.String()),
	)

	if bootstrapPathDiffers {
		return fmt.Errorf("cluster already bootstrapped to %v path", usedPath)
	}

	// Manifest base
	// TODO(hidde): move?
	if ver, err := getVersion(bootstrapArgs.version); err != nil {
		return err
	} else {
		bootstrapArgs.version = ver
	}

	manifestsBase := ""
	if isEmbeddedVersion(bootstrapArgs.version) {
		tmpBaseDir, err := ioutil.TempDir("", "flux-manifests-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpBaseDir)
		if err := writeEmbeddedManifests(tmpBaseDir); err != nil {
			return err
		}
		manifestsBase = tmpBaseDir
	}

	// GitHub provider
	var providerOpts []github.ClientOption
	providerOpts = append(providerOpts, github.WithOAuth2Token(ghToken))
	if githubArgs.hostname != "" {
		providerOpts = append(providerOpts, github.WithDomain(githubArgs.hostname))
	}
	provider, err := github.NewClient(providerOpts...)
	if err != nil {
		return err
	}

	// Lazy go-git repository
	tmpDir, err := ioutil.TempDir("", "flux-bootstrap-")
	if err != nil {
		return fmt.Errorf("failed to create temporary working dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	repo := gogit.New(tmpDir, &http.BasicAuth{
		Username: githubArgs.owner,
		Password: ghToken,
	})

	// Init bootstrap
	b, err := bootstrap.NewBootstrap(repo, provider, logger, rootArgs.pollInterval, rootArgs.timeout, rootArgs.kubeconfig, rootArgs.kubecontext)
	if err != nil {
		return err
	}

	// Repository config
	var repoOpts gitprovider.RepositoryRef
	switch githubArgs.personal {
	case false:
		repoOpts = gitprovider.OrgRepositoryRef{
			OrganizationRef: gitprovider.OrganizationRef{
				Domain:       githubArgs.hostname,
				Organization: githubArgs.owner,
			},
			RepositoryName: githubArgs.repository,
		}
	default:
		// TODO(hidde): add support upstream for custom SSH hostname (and/or port)
		repoOpts = gitprovider.UserRepositoryRef{
			UserRef: gitprovider.UserRef{
				Domain:    githubArgs.hostname,
				UserLogin: githubArgs.owner,
			},
			RepositoryName: githubArgs.repository,
		}
	}
	// TODO(hidde): configure "public" flag
	repoInfo := &gitprovider.RepositoryInfo{
		DefaultBranch: gitprovider.StringVar(bootstrapArgs.branch),
	}

	// Install manifest config
	installOptions := install.Options{
		BaseURL:                rootArgs.defaults.BaseURL,
		Version:                bootstrapArgs.version,
		Namespace:              rootArgs.namespace,
		Components:             bootstrapComponents(),
		Registry:               bootstrapArgs.registry,
		ImagePullSecret:        bootstrapArgs.imagePullSecret,
		WatchAllNamespaces:     bootstrapArgs.watchAllNamespaces,
		NetworkPolicy:          bootstrapArgs.networkPolicy,
		LogLevel:               bootstrapArgs.logLevel.String(),
		NotificationController: rootArgs.defaults.NotificationController,
		ManifestFile:           rootArgs.defaults.ManifestFile,
		Timeout:                rootArgs.timeout,
		TargetPath:             githubArgs.path.String(),
		ClusterDomain:          bootstrapArgs.clusterDomain,
		TolerationKeys:         bootstrapArgs.tolerationKeys,
	}
	if customBaseURL := bootstrapArgs.manifestsPath; customBaseURL != "" {
		installOptions.BaseURL = customBaseURL
	}

	// Source generation and secret config
	secretOpts := sourcesecret.Options{
		Name:         rootArgs.namespace,
		Namespace:    rootArgs.namespace,
		TargetPath:   githubArgs.path.String(),
		ManifestFile: sourcesecret.MakeDefaultOptions().ManifestFile,
	}
	if bootstrapArgs.tokenAuth {
		secretOpts.Username = "git"
		secretOpts.Password = ghToken
	} else {
		secretOpts.PrivateKeyAlgorithm = sourcesecret.RSAPrivateKeyAlgorithm
		secretOpts.RSAKeyBits = 2048
		secretOpts.SSHHostname = githubArgs.hostname

		if githubArgs.sshHostname != "" {
			secretOpts.SSHHostname = githubArgs.sshHostname
		}
	}

	// Sync manifest config
	syncOpts := sync.Options{
		Interval: githubArgs.interval,
		// TODO(hidde): support token auth
		URL:               repoOpts.GetCloneURL(gitprovider.TransportTypeSSH),
		Name:              rootArgs.namespace,
		Namespace:         rootArgs.namespace,
		Branch:            bootstrapArgs.branch,
		Secret:            rootArgs.namespace,
		TargetPath:        githubArgs.path.String(),
		ManifestFile:      sync.MakeDefaultOptions().ManifestFile,
		GitImplementation: sourceGitArgs.gitImplementation.String(),
	}

	// Run
	return b.Reconcile(ctx, manifestsBase, installOptions, secretOpts, syncOpts, repoOpts, repoInfo)
}
