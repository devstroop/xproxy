# xproxy

Workspace boilerplate — no major implementation.

## Layout

```
xproxy/
├── Cargo.toml          # workspace + binary `xproxy` (src/main.rs)
├── src/main.rs         # minimal entrypoint wiring core/forward/reverse
└── crates/
    ├── core/           # xproxy-core — Config, Error, Proxy trait
    ├── forward/        # xproxy-forward — ForwardProxy stub
    └── reverse/        # xproxy-reverse — ReverseProxy stub
```

## Build

```sh
cargo check
cargo build
cargo run
cargo fmt --check
cargo clippy -- -D warnings
```
# xproxy
