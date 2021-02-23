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

package gogit

import (
	"context"
	"io"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/fluxcd/flux2/pkg/bootstrap/git"
)

type goGit struct {
	path       string
	auth       transport.AuthMethod
	repository *gogit.Repository
}

func New(path string, auth transport.AuthMethod) git.Git {
	return &goGit{
		path: path,
		auth: auth,
	}
}

func (g *goGit) Init(url, branch string) (bool, error) {
	if g.repository != nil {
		return false, nil
	}

	r, err := gogit.PlainInit(g.path, false)
	if err != nil {
		return false, err
	}
	if _, err = r.CreateRemote(&config.RemoteConfig{
		Name: gogit.DefaultRemoteName,
		URLs: []string{url},
	}); err != nil {
		return false, err
	}
	branchRef := plumbing.NewBranchReferenceName(branch)
	if err = r.CreateBranch(&config.Branch{
		Name:   branch,
		Remote: gogit.DefaultRemoteName,
		Merge:  branchRef,
	}); err != nil {
		return false, err
	}
	// PlainInit assumes the initial branch to always be master, we can
	// overwrite this by setting the reference of the Storer to a new
	// symbolic reference (as there are no commits yet) that points
	// the HEAD to our new branch.
	if err = r.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchRef)); err != nil {
		return false, err
	}

	g.repository = r
	return true, nil
}

func (g *goGit) Clone(ctx context.Context, url, branch string) (bool, error) {
	r, err := gogit.PlainCloneContext(ctx, g.path, false, &gogit.CloneOptions{
		URL:           url,
		Auth:          g.auth,
		RemoteName:    gogit.DefaultRemoteName,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,

		NoCheckout: false,
		Progress:   nil,
		Tags:       gogit.NoTags,
	})
	if err != nil {
		if err == transport.ErrEmptyRemoteRepository {
			return g.Init(url, branch)
		}
		return false, err
	}

	g.repository = r
	return true, nil
}

func (g *goGit) Write(path string, reader io.Reader) error {
	if g.repository == nil {
		return git.ErrNoGitRepository
	}

	wt, err := g.repository.Worktree()
	if err != nil {
		return err
	}

	f, err := wt.Filesystem.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, reader)
	return err
}

func (g *goGit) Commit(message git.Commit) (string, error) {
	if g.repository == nil {
		return "", git.ErrNoGitRepository
	}

	wt, err := g.repository.Worktree()
	if err != nil {
		return "", err
	}

	status, err := wt.Status()
	if err != nil {
		return "", err
	}
	if status.IsClean() {
		head, err := g.repository.Head()
		if err != nil {
			return "", err
		}
		return head.Hash().String(), git.ErrNoStagedFiles
	}
	if _, err = wt.Add("."); err != nil {
		return "", err
	}

	commit, err := wt.Commit(message.Message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  message.Name,
			Email: message.Email,
			When:  time.Now(),
		},
	})
	if err != nil {
		return "", err
	}
	return commit.String(), nil
}

func (g *goGit) Push(ctx context.Context) error {
	if g.repository == nil {
		return git.ErrNoGitRepository
	}

	return g.repository.PushContext(ctx, &gogit.PushOptions{
		RemoteName: gogit.DefaultRemoteName,
		Auth:       g.auth,
		Progress:   nil,
	})
}

func (g *goGit) Status() (bool, error) {
	if g.repository == nil {
		return false, git.ErrNoGitRepository
	}
	wt, err := g.repository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := wt.Status()
	if err != nil {
		return false, err
	}
	return status.IsClean(), nil
}

func (g *goGit) Path() string {
	return g.path
}
