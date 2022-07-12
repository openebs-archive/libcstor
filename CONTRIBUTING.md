# Contributing to libcstor

libcstor is an open-source project.

libcstor uses the standard GitHub pull requests process to review and accept contributions.

You can contribute to libcstor by filling an issue at [openebs/libcstor](https://github.com/openebs/libcstor/issues) or submitting a pull request to this repository.

* If you want to file an issue for bug or feature request, please see [Filing an issue](#filing-an-issue)
* If you are a first-time contributor, please see [Steps to Contribute](#steps-to-contribute) and code standard(code-standard.md).
* If you would like to work on something more involved, please connect with the OpenEBS Contributors. See [OpenEBS Community](https://github.com/openebs/openebs/tree/HEAD/community)

## Filing an issue
### Before filing an issue

If you are unsure whether you have found a bug, please consider asking in the [Slack](https://kubernetes.slack.com/messages/openebs) first. If
the behavior you are seeing is confirmed as a bug or issue, it can easily be re-raised in the [issue tracker](https://github.com/openebs/libcstor/issues).

### Filing issues

When filing an issue, make sure to answer these five questions:

1. What version of OpenEBS are you using?
2. What steps did you follow for using cstor?
3. What did you expect to see?
4. What did you see instead?
5. Logs of cstor pod and target pod

#### For maintainers
* We are using labeling for the issue to track it more effectively. The following are valid labels for the issue.
   - **Bug** - If the issue is a **bug to existing feature**
   - **Enhancement** - If the issue is a **feature request**
   - **Maintenance**  - If the issue is not related to production code. **build, document or test related issues fall into this category**
   - **Question** - If the issue is about **querying information about how the product or build works, or internal of product**.
   - **Documentation** - If the issue is about **tracking the documentation work for the feature**. This label should not be applied to the issue of a bug in documentations.
   - **Good First Issue** - If the issue is easy to get started with. Please make sure that the issue should be ideal for beginners to dive into the codebase.
   - **Design** - if the issue **needs a design decision prior to code implementation**
   - **Duplicate** - if the issue is **duplicate of another issue**

* We are using the following labels for issue work-flow:
   - **Backlog** - if the issue has **not been planned for current release cycle**
   - **Release blocker** - if the issue is **blocking the release**
   - **Priority: high** - issue with this label **should be resolved as quickly as possible**
   - **Priority: low** - issue with this label **won’t have the immediate focus of the core team**

**If you want to introduce a new label then you need to raise a PR to update this document with the new label details.**

## Steps to Contribute
libcstor is an Apache 2.0 Licensed project and all your commits should be signed with Developer Certificate of Origin. See [Sign your work](#sign-your-work).

For setting up a development environment on your local machine, see the detailed instructions [here](developer-setup.md).

* Find an issue to work on or create a new issue. The issues are maintained at [openebs/libcstor](https://github.com/openebs/libcstor/issues). You can pick up from a list of [good-first-issues](https://github.com/openebs/libcstor/labels/good%20first%20issue).
* Claim your issue by commenting your intent to work on it to avoid duplication of efforts.
* Fork the repository on GitHub.
* Create a branch from where you want to base your work (usually develop).
* Commit your changes by making sure the commit messages convey the need and notes about the commit.
* Please make sure than your code is aligned with the standard mentioned at [code-standard](code-standard.md).
* Push your changes to the branch in your fork of the repository.
* Submit a pull request to the original repository. See [Pull Request checklist](#pull-request-checklist)

## Pull Request Checklist
* Rebase to the current develop branch before submitting your pull request.
* Commits should be as small as possible. Each commit should follow the checklist below:
  - For code changes, add tests relevant to the fixed bug or new feature.
  - Commit header (first line) should convey what changed
  - Commit body should include details such as why the changes are required and how the proposed changes help
  - DCO Signed, please refer [signing commit](code-standard.md#sign-your-commits)
* If your PR is about fixing an issue or new feature, make sure you add a change-log. Refer [Adding a Change log](code-standard.md#adding-a-changelog)
* PR title must follow convention: `<type>(<scope>): <subject>`.

  For example:
  ```
   feat(snapshot): support for snapshot
   ^--^ ^-----^   ^-----------------------^
     |     |         |
     |     |         +-> PR subject, summary of the changes
     |     |
     |     +-> scope of the PR, i.e. component of the project this PR is intend to update
     |
     +-> type of the PR.
  ```

    Most common types are:
    * `feat`        - for new features, not a new feature for build script
    * `fix`         - for bug fixes or improvements, not a fix for build script
    * `chore`       - changes not related to production code
    * `docs`        - changes related to documentation
    * `style`       - formatting, missing semi colons, linting fix etc; no significant production code changes
    * `test`        - adding missing tests, refactoring tests; no production code change
    * `refactor`    - refactoring production code, eg. renaming a variable or function name, there should not be any significant production code changes
    * `cherry-pick` - if PR is merged in develop branch and raised to release branch(like v1.9.x)

---

### Sign your work

We use the Developer Certificate of Origin (DCO) as an additional safeguard for the OpenEBS project. This is a well established and widely used mechanism to assure contributors have confirmed their right to license their contribution under the project's license. Please read [developer-certificate-of-origin](./contribute/developer-certificate-of-origin).

Please certify it by just adding a line to every git commit message. Any PR with Commits which does not have DCO Signoff will not be accepted:

```
  Signed-off-by: Random J Developer <random@developer.example.org>
```

or use the command `git commit -s -m "commit message comes here"` to sign-off on your commits.

Use your real name (sorry, no pseudonyms or anonymous contributions). If you set your `user.name` and `user.email` git configs, you can sign your commit automatically with `git commit -s`. You can also use git [aliases](https://git-scm.com/book/en/v2/Git-Basics-Git-Aliases) like `git config --global alias.ci 'commit -s'`. Now you can commit with `git ci` and the commit will be signed.

---

## Code Reviews
All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests) for more information on using pull requests.

* If your PR is not getting reviewed or you need a specific person to review it, please reach out to the OpenEBS Contributors. See [OpenEBS Community](https://github.com/openebs/openebs/tree/HEAD/community)

* If PR is fixing any issues from [github-issues](github.com/openebs/libcstor/issues) then you need to mention the issue number with a link in the PR description. like: _fixes https://github.com/openebs/libcstor/issues/56_

* If PR is for bug-fix and release branch(like v1.9.x) is created then cherry-pick for the same PR needs to be created against the release branch. Maintainer of the Project needs to make sure that all the bug fixes, after an RC release, are cherry-picked to release branch and their changelog files are created under `changelogs/v1.9.x` instead of `changelogs/unreleased`, if release branch is `v1.10.x` then this folder will be `changelogs/v1.10.x`.

### For maintainers
* We are using labeling for PR to track it more effectively. The following are valid labels for the PR.
   - **Bug** - if PR is a **bug to existing feature**
   - **Enhancement** - if PR is a **feature request**
   - **Maintenance**  - if PR is not related to production code. **build, document or test related PR falls into this category**
   - **Documentation** - if PR is about **tracking the documentation work for the feature**. This label should not be applied to the PR fixing bug in documentations.

* We are using the following label for PR work-flow:
   - **DO NOT MERGE** - if PR is about critical changes and no scope of testing before release branch creation
   - **On Hold** - if PR doesn't have sufficient changes, all the scenarios are not covered or changes are requested from contributor
   - **Release blocker** - if PR is created for the issue having label **Release blocker**
   - **Priority: high** - if PR is created for the issue having label **Priority: high**
   - **Priority: low** - if PR is created for the issue having label **Priority: low**

* Maintainer needs to make sure that appropriate milestone and project tracker is assigned to the PR.

**If you want to introduce a new label then you need to raise a PR to update this document with the new label details.**
