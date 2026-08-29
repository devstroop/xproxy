# xproxy

Dual-mode proxy — forward (egress: HTTP/HTTPS/SOCKS) and reverse (ingress: routing, LB, TLS) on a single binary with policy-based destination resolution. Currently workspace boilerplate only; implementation gated behind GitHub Discussions.

## Workspace layout

```
xproxy/
├── Cargo.toml                    # workspace (members crates/*) + binary xproxy [[bin]] src/main.rs
├── rustfmt.toml                  # edition 2024, stable opts
├── .gitignore                    # /target, env/config, TLS secrets, IDE
├── .github/
│   ├── workflows/ci.yml          # fmt+clippy+check+test+deny/audit/semver
│   ├── CONTRIBUTING.md           # gated workflow
│   ├── pull_request_template.md
│   └── ISSUE_TEMPLATE/           # require Discussion first
├── src/main.rs                   # minimal wiring of xproxy-core/forward/reverse
├── crates/
│   ├── core/                     # xproxy-core — Config, Error, Proxy trait (lean)
│   ├── forward/                  # xproxy-forward — ForwardProxy stub
│   └── reverse/                  # xproxy-reverse — ReverseProxy stub
└── docs/CONTEXT.md               # pointer to Discussions (not synthesis)
```

Scaffold is `xproxy-core v0.1.0` with `Proxy {mode,name}`, `Config {listen_addr}`, `Error(String)` — to be replaced via RFCs.

## Build

```sh
cargo check --all-targets
cargo build
cargo run
cargo test --all-targets
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

No heavy deps in `core` (only `serde`/`thiserror`/`tracing`). Requires `rust 1.85+`, `edition 2024`.

## Development workflow — gated

```
main (protected, prod) <- develop (integration) <- feat/* fix/* chore/* docs/*
```

- `main` and `develop` are protected: PR required, 1 approval, dismiss stale, conversation resolution, `allow_force_pushes:false`. `enforce_admins:false` for bootstrap only.
- All work goes through `feat/*` worktrees, never direct to `main`/`develop`.

**Worktrees (isolated, sibling dirs):**

```sh
git fetch origin
git checkout develop && git pull
git checkout -b feat/<topic> develop
git worktree add ../xproxy-feat-<topic> feat/<topic>
# work in ../xproxy-feat-<topic>, push, open PR feat/<topic> -> develop
git worktree list
# after squash merge:
git worktree remove ../xproxy-feat-<topic> && git branch -d feat/<topic>
```

Current primary: `xproxy` `[develop]`, mirror `xproxy-main` `[main]`. See `.github/CONTRIBUTING.md:1`.

**Flow:** Discussion → Issue → `feat/*` worktree → PR `feat/* -> develop` → CI → squash → periodic `develop -> main` release.

## Discussions & Issues

- **Source of truth:** GitHub Discussions #1–#6 (General/Ideas) on `devstroop/xproxy`:
  - #1 Engine architecture — unified engine vs policy
  - #2 Forward proxy — protocol handling
  - #3 Reverse proxy — routing/LB/TLS
  - #4 Core primitives — config/error
  - #5 Branching & collaboration — gated workflow
  - #6 Security & deployment
- **Superseded:** `[META]` synthesis (#7) was in-chat speculative and is not canonical.
- **Issues:** #8–#13 Epics + #14–#39 subs are `blocked:rfc`/`question` draft pending RFC consensus. No `feat/*` for proxy stack until Discussions close. See `docs/CONTEXT.md:1`.

In-chat discussion materials are reference only and potentially inaccurate — keep GitHub Discussions separate.

## Contributing

See `.github/CONTRIBUTING.md` and `.github/pull_request_template.md`. Issues require linked Discussion (`ISSUE_TEMPLATE/config.yml`). CI must pass (`ci` workflow on push/PR to `main`/`develop`).
