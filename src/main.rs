use std::sync::Arc;

use tokio::sync::Semaphore;
use xproxy_core::{Config, Mode, Orchestrator, Proxy};
use xproxy_forward::ForwardProxy;
use xproxy_reverse::ReverseProxy;

/// Global limits at TCP accept — placeholder for `tower::limit::ConcurrencyLimit`.
#[derive(Debug)]
struct Limits {
    global: Arc<Semaphore>,
}

impl Limits {
    fn new(limit: usize) -> Self {
        Self { global: Arc::new(Semaphore::new(limit)) }
    }
}

#[tokio::main]
async fn main() -> xproxy_core::Result<()> {
    let config = Config::default();
    config.validate()?;

    let limits = Arc::new(Limits::new(1024));
    let mut orch = Orchestrator::new();
    let token = orch.token();

    // Spawn per-mode tasks based on Config::mode and listen addresses.
    // For now, stub tasks that simulate listeners; real listeners will use `Config` addresses.
    match config.mode {
        Mode::Both | Mode::Forward => {
            if let Some(addr) = config.listen_forward.clone() {
                let limits = limits.clone();
                let token = token.clone();
                orch.spawn(async move {
                    let _permit = limits.global.clone().try_acquire_owned().ok();
                    println!("forward listener stub on {addr} (mode: forward)");
                    // Real: TcpListener::bind(addr).await, accept loop with token.cancelled()
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {},
                        _ = token.cancelled() => {
                            println!("forward listener shutdown");
                        }
                    }
                });
            } else {
                let fwd = ForwardProxy::new(config.clone());
                println!("forward proxy registered: {} (no listen addr)", fwd.name());
            }
        }
        _ => {}
    }

    match config.mode {
        Mode::Both | Mode::Reverse => {
            if let Some(addr) = config.listen_reverse.clone() {
                let limits = limits.clone();
                let token = token.clone();
                orch.spawn(async move {
                    let _permit = limits.global.clone().try_acquire_owned().ok();
                    println!("reverse listener stub on {addr} (mode: reverse)");
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {},
                        _ = token.cancelled() => {
                            println!("reverse listener shutdown");
                        }
                    }
                });
            } else {
                let rev = ReverseProxy::new(config.clone());
                println!("reverse proxy registered: {} (no listen addr)", rev.name());
            }
        }
        _ => {}
    }

    // If no listeners spawned, just report and exit.
    if orch.task_count() == 0 {
        let fwd = ForwardProxy::new(config.clone());
        let rev = ReverseProxy::new(config);
        println!("xproxy — proxies registered: {}, {}", fwd.name(), rev.name());
        println!("mode check: {:?} / {:?}", fwd.mode(), rev.mode());
        return Ok(());
    }

    println!(
        "xproxy orchestrator running with {} tasks, press Ctrl-C to shutdown",
        orch.task_count()
    );

    // Graceful shutdown on SIGTERM/SIGINT (Ctrl-C).
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("shutdown signal received");
            orch.shutdown();
        }
        _ = token.cancelled() => {
            println!("orchestrator cancelled");
        }
    }

    orch.wait().await;
    println!("xproxy shutdown complete");
    Ok(())
}
