<!--- Link Discussion + Issue, keep unbiased --->

## Linked Discussion / Issue
Closes # (issue)
Related Discussion: (url)

## Scope
- [ ] Forward (SOCKS/HTTP/CONNECT/MITM)
- [ ] Reverse (router/LB/TLS)
- [ ] Core (config/error/tls)
- [ ] Workflow/CI/Docs

## Branch Gating
- [ ] Source is `feat/*`/`fix/*`/`chore/*` -> `develop` (or `develop` -> `main` for release)
- [ ] Worktree: `../xproxy-<branch>` isolated

## Checklist
- [ ] `cargo fmt --check` pass
- [ ] `cargo clippy --all-targets -- -D warnings` pass
- [ ] `cargo check --all-targets` pass
- [ ] `cargo test` pass
- [ ] No in-chat speculative stack without Discussion consensus
- [ ] No direct push to `main`/`develop`

## Verification
```
cargo check
cargo test
```

## Notes for Reviewer
