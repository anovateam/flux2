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

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/spf13/cobra"

	"github.com/fluxcd/flux2/internal/flags"
	"github.com/fluxcd/flux2/internal/utils"
	"github.com/fluxcd/flux2/pkg/bootstrap"
	"github.com/fluxcd/flux2/pkg/bootstrap/git/gogit"
	"github.com/fluxcd/flux2/pkg/bootstrap/provider"
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
	owner        string
	repository   string
	interval     time.Duration
	personal     bool
	private      bool
	hostname     string
	sshHostname  string
	path         flags.SafeRelativePath
	teams        []string
	readWriteKey bool
}

const (
	ghDefaultPermission = "maintain"
	ghDefaultDomain     = "github.com"
	ghTokenEnvVar       = "GITHUB_TOKEN"
)

var githubArgs githubFlags

func init() {
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.owner, "owner", "", "GitHub user or organization name")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.repository, "repository", "", "GitHub repository name")
	bootstrapGitHubCmd.Flags().StringArrayVar(&githubArgs.teams, "team", []string{}, "GitHub team to be given maintainer access")
	bootstrapGitHubCmd.Flags().BoolVar(&githubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	bootstrapGitHubCmd.Flags().BoolVar(&githubArgs.private, "private", true, "if true, the repository is assumed to be private")
	bootstrapGitHubCmd.Flags().DurationVar(&githubArgs.interval, "interval", time.Minute, "sync interval")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.hostname, "hostname", ghDefaultDomain, "GitHub hostname")
	bootstrapGitHubCmd.Flags().StringVar(&githubArgs.sshHostname, "ssh-hostname", "", "GitHub SSH hostname, to be used when the SSH host differs from the HTTPS one")
	bootstrapGitHubCmd.Flags().Var(&githubArgs.path, "path", "path relative to the repository root, when specified the cluster sync will be scoped to this path")
	bootstrapGitHubCmd.Flags().BoolVar(&githubArgs.readWriteKey, "read-write-key", false, "if true, the deploy key is configured with read/write permissions")

	bootstrapCmd.AddCommand(bootstrapGitHubCmd)
}

func bootstrapGitHubCmdRun(cmd *cobra.Command, args []string) error {
	ghToken := os.Getenv(ghTokenEnvVar)
	if ghToken == "" {
		return fmt.Errorf("%s environment variable not found", ghTokenEnvVar)
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

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider:    provider.GitProviderGitHub,
		Hostname:    githubArgs.hostname,
		SSHHostname: githubArgs.sshHostname,
		Token:       ghToken,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	// Lazy go-git repository
	tmpDir, err := ioutil.TempDir("", "flux-bootstrap-")
	if err != nil {
		return fmt.Errorf("failed to create temporary working dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	gitClient := gogit.New(tmpDir, &http.BasicAuth{
		Username: githubArgs.owner,
		Password: ghToken,
	})

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
		Interval:          githubArgs.interval,
		Name:              rootArgs.namespace,
		Namespace:         rootArgs.namespace,
		Branch:            bootstrapArgs.branch,
		Secret:            rootArgs.namespace,
		TargetPath:        githubArgs.path.String(),
		ManifestFile:      sync.MakeDefaultOptions().ManifestFile,
		GitImplementation: sourceGitArgs.gitImplementation.String(),
	}

	// Bootstrap config
	bootstrapOpts := []bootstrap.GitProviderOption{
		bootstrap.WithProviderRepository(githubArgs.owner, githubArgs.repository, githubArgs.personal),
		bootstrap.WithBranch(bootstrapArgs.branch),
		bootstrap.WithBootstrapTransportType("https"),
		bootstrap.WithAuthor("Flux", githubArgs.owner+"@users.noreply.github.com"),
		bootstrap.WithProviderTeamPermissions(mapTeamSlice(githubArgs.teams)),
		bootstrap.WithReadWriteKeyPermissions(githubArgs.readWriteKey),
		bootstrap.WithKubeconfig(rootArgs.kubeconfig, rootArgs.kubecontext),
		bootstrap.WithLogger(logger),
	}
	if githubArgs.sshHostname != "" {
		bootstrapOpts = append(bootstrapOpts, bootstrap.WithSSHHostname(githubArgs.sshHostname))
	}
	if bootstrapArgs.tokenAuth {
		bootstrapOpts = append(bootstrapOpts, bootstrap.WithSyncTransportType("https"))
	}
	if bootstrapArgs.authorName != "" || bootstrapArgs.authorEmail != "" {
		bootstrapOpts = append(bootstrapOpts, bootstrap.WithAuthor(bootstrapArgs.authorName, bootstrapArgs.authorEmail))
	}
	if !githubArgs.private {
		bootstrapOpts = append(bootstrapOpts, bootstrap.WithProviderRepositoryConfig("", "", "public"))
	}

	// Setup bootstrapper with constructed configs
	b, err := bootstrap.NewGitProviderBootstrapper(gitClient, providerClient, kubeClient, bootstrapOpts...)
	if err != nil {
		return err
	}

	// Run
	return bootstrap.Run(ctx, b, manifestsBase, installOptions, secretOpts, syncOpts, rootArgs.pollInterval, rootArgs.timeout)
}

func mapTeamSlice(s []string) map[string]string {
	m := make(map[string]string, len(s))
	for _, v := range s {
		m[v] = ghDefaultPermission
	}
	return m
}
