//! Concurrency limits — per-upstream `Semaphore` + global limit at TCP accept.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// Limits for reverse proxy.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    global: Arc<Semaphore>,
    global_limit: usize,
    per_upstream: HashMap<String, Arc<Semaphore>>,
    per_upstream_limit: usize,
}

impl ConcurrencyLimiter {
    pub fn new(global_limit: usize, per_upstream_limit: usize, upstreams: Vec<String>) -> Self {
        let limit = global_limit.max(1);
        let per = per_upstream_limit.max(1);
        let global = Arc::new(Semaphore::new(limit));
        let mut per_upstream = HashMap::new();
        for name in upstreams {
            per_upstream.insert(name, Arc::new(Semaphore::new(per)));
        }
        Self { global, global_limit: limit, per_upstream, per_upstream_limit: per }
    }

    pub fn global_limit(&self) -> usize {
        self.global_limit
    }

    /// Try acquire both global and per-upstream. Returns permits if available.
    pub fn try_acquire(
        &self,
        upstream: &str,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), TryAcquireError> {
        let global_permit = self.global.clone().try_acquire_owned()?;
        let upstream_sem = self
            .per_upstream
            .get(upstream)
            .cloned()
            .unwrap_or_else(|| Arc::new(Semaphore::new(self.per_upstream_limit)));
        let upstream_permit = upstream_sem.try_acquire_owned()?;
        Ok((global_permit, upstream_permit))
    }

    pub fn available_global(&self) -> usize {
        self.global.available_permits()
    }

    pub fn available_upstream(&self, upstream: &str) -> usize {
        self.per_upstream
            .get(upstream)
            .map(|s| s.available_permits())
            .unwrap_or(self.per_upstream_limit)
    }

    pub fn per_upstream_limit(&self) -> usize {
        self.per_upstream_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_limit() {
        let lim = ConcurrencyLimiter::new(2, 1, vec!["a".into(), "b".into()]);
        let _p1 = lim.try_acquire("a").unwrap();
        let _p2 = lim.try_acquire("b").unwrap();
        assert!(lim.try_acquire("a").is_err()); // global exhausted
    }

    #[test]
    fn per_upstream_limit() {
        let lim = ConcurrencyLimiter::new(10, 1, vec!["a".into()]);
        let _p1 = lim.try_acquire("a").unwrap();
        assert!(lim.try_acquire("a").is_err()); // per-upstream exhausted
        assert!(lim.try_acquire("b").is_ok()); // different upstream ok (fallback creates new)
    }

    #[test]
    fn release_on_drop() {
        let lim = ConcurrencyLimiter::new(1, 1, vec!["a".into()]);
        {
            let _p = lim.try_acquire("a").unwrap();
            assert_eq!(lim.available_global(), 0);
        }
        assert_eq!(lim.available_global(), 1);
    }
}
