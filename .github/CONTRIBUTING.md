# Contributing to xproxy

## Branch Gating

```
main (protected, prod) <- develop (integration) <- feat/* fix/* chore/* docs/*
```

- `main`: production, protected. Only merges from `develop` via PR. Requires CI + 1 approval.
- `develop`: integration, protected. Only merges from `feat/*`/`fix/*`/`chore/*` via PR. Requires CI + 1 approval.
- `feat/*`, `fix/*`, `chore/*`, `docs/*`: per-issue worktrees. Naming: `feat/forward-demux`, `fix/security-crlf`, `chore/ci`.

## Worktree usage

For parallel group work:

```sh
git fetch origin
git checkout develop && git pull
git checkout -b feat/<topic>
git worktree add ../xproxy-feat-<topic> feat/<topic>
# work in ../xproxy-feat-<topic>, push, open PR feat/<topic> -> develop
```

List: `git worktree list`. Remove: `git worktree remove ../xproxy-feat-<topic> && git branch -d feat/<topic>`.

## Discussion -> Issue -> PR flow

1. **Discussion**: Open GitHub Discussion (General/Ideas) for design. Do not code until consensus.
2. **Issue**: After consensus, create Issue linked to Discussion. Add `blocked:rfc` until RFC closed, then assign.
3. **Branch/PR**: Create `feat/*` worktree, implement, open PR to `develop`. Link Discussion + Issue.
4. **CI**: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo check --all-targets`, `cargo test` must pass. `deny`/`audit`/`semver` continue-on-error during bootstrap.
5. **Merge**: Squash to `develop`. Periodically `develop -> main` release PR.

## Professional standard

- Present trade-offs neutrally, list alternatives.
- In-chat synthesis is not canonical — GitHub Discussions #1–#6 are source.
- Keep `docs/CONTEXT.md` as pointer only.
