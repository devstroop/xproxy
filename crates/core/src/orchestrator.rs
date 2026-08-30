//! Orchestrator — JoinSet + CancellationToken skeleton.

use std::sync::Arc;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Orchestrator manages listener tasks with graceful shutdown.
#[derive(Debug)]
pub struct Orchestrator {
    tasks: JoinSet<()>,
    shutdown: CancellationToken,
}

impl Orchestrator {
    pub fn new() -> Self {
        Self { tasks: JoinSet::new(), shutdown: CancellationToken::new() }
    }

    pub fn token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub fn spawn<F>(&mut self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token = self.shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                _ = fut => {},
                _ = token.cancelled() => {},
            }
        });
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn wait(&mut self) {
        while self.tasks.join_next().await.is_some() {}
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_cancelled()
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-mode isolated state placeholder — avoids single Engine<AppState> lock contention.
#[derive(Debug, Default, Clone)]
pub struct ModeState {
    pub name: String,
}

impl ModeState {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

pub type SharedModeState = Arc<ModeState>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let mut orch = Orchestrator::new();
        assert_eq!(orch.task_count(), 0);
        orch.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        assert_eq!(orch.task_count(), 1);
        orch.shutdown();
        orch.wait().await;
        assert!(orch.is_shutting_down());
    }

    #[tokio::test]
    async fn token_cancel() {
        let orch = Orchestrator::new();
        let token = orch.token();
        assert!(!token.is_cancelled());
        orch.shutdown();
        assert!(token.is_cancelled());
    }
}
