# Branching, pull requests and releases

The project uses **trunk-based development with short-lived branches**
(GitHub Flow). `master` is always releasable; every change reaches it through
a reviewed pull request with green CI; releases are git tags on `master`.

```
master ──●─────────●───────────●──────────●────▶   (protected, always green)
          \       /  \        /            \
           feature/sigma-engine  fix/ws-reconnect   tag v0.4.0 → release
```

## Branches

| Prefix | Use for | Example |
|---|---|---|
| `feature/` | New capability or user-visible improvement | `feature/sigma-detection-engine` |
| `fix/` | Bug fix | `fix/syslog-tcp-framing` |
| `hotfix/` | Urgent fix for a released version | `hotfix/auth-bypass` |
| `chore/` | Maintenance, dependencies, tooling | `chore/bump-go-1-26` |
| `docs/` | Documentation only | `docs/detection-guide` |
| `ci/` | Workflows and automation | `ci/cache-npm` |
| `refactor/` | Internal change, no behaviour change | `refactor/store-interface` |
| `dependabot/` | Created by Dependabot only | — |

Names are lowercase kebab-case: `<prefix>/<short-name>` matching
`^(feature|fix|hotfix|chore|docs|ci|refactor)/[a-z0-9][a-z0-9-]*$`.
Branch from the latest `master`, keep the branch small (ideally under a few
days of work) and delete it after merge.

## Pull requests

- **Title = branch name**, e.g. `feature/sigma-detection-engine`. The
  `PR checks` workflow enforces this and the naming pattern above.
- **Labels are automatic**: a `type:` label from the branch prefix and
  `area:` labels from the changed paths. Add `priority:` and status labels
  by hand when useful.
- Fill in the PR template: what and why, how it was tested.
- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `ci:` …); the `commit-msg` hook checks this.
- One logical change per PR. Split unrelated work into separate PRs.

### Merge requirements (`master` protection)

A PR merges only when all of these hold:

1. CI is green: `Go (vet, lint, test, build)`, `Go integration (Postgres + Qdrant)`,
   `Web (lint, typecheck, test, build)`, `PR title and branch`, `CodeQL`,
   `govulncheck`, `Secret scan`.
2. At least one approving review from a code owner (`.github/CODEOWNERS`).
3. All review conversations resolved.
4. The branch is up to date with `master`.

Merges use **merge commits** titled `<branch> (#<pr>)`, which keeps each PR
visible as one unit in history. Force-pushes to `master` and deleting it are
blocked.

### Setting up protection (repository admin, once)

Settings → Rules → Rulesets → **New branch ruleset**:

- Target: default branch (`master`), enforcement **Active**.
- Enable: *Restrict deletions*, *Block force pushes*,
  *Require a pull request before merging* (1 approval, require review from
  Code Owners, dismiss stale approvals, require conversation resolution),
  *Require status checks to pass* (add the checks listed above, and
  *require branches to be up to date*).
- Settings → General → Pull Requests: allow merge commits, enable
  *Automatically delete head branches*.
- Settings → Code security: enable *Dependabot alerts*, *Secret scanning*
  with *Push protection*, and *Private vulnerability reporting*.

## Releases

Versions follow [Semantic Versioning](https://semver.org/). To release:

```bash
git checkout master && git pull
git tag -a v0.4.0 -m "v0.4.0"
git push origin v0.4.0
```

The `Release` workflow then runs the quality gate, builds binaries for
Linux and macOS (amd64/arm64) with checksums, publishes container images to
GHCR (`ghcr.io/chanchalvdev/siemagent-api`, `ghcr.io/chanchalvdev/siemagent-web`)
and creates a GitHub release with generated notes grouped by label.

Hotfixes branch from the release tag (`hotfix/<name>`), merge to `master`
through a PR, and are released as the next patch version.

## Local hooks

`make hooks` (from the repository root) points git at `.githooks/`:

| Hook | Checks |
|---|---|
| `pre-commit` | gofmt on staged Go files, oxlint on staged web files, no `.env` files |
| `commit-msg` | Conventional Commit format |
| `pre-push` | branch name pattern, `go vet` and Go unit tests |

Hooks are a fast local safety net; CI remains the source of truth.
