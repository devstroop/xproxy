//! Load balancing selector — RR v1, P2C stub for upgrade without rewrite.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Minimal upstream handle for selection. Real upstream (health, weight) lives elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub name: String,
    pub url: String,
    pub weight: u32,
}

impl Upstream {
    pub fn new(name: impl Into<String>, url: impl Into<String>, weight: u32) -> Self {
        Self { name: name.into(), url: url.into(), weight: weight.max(1) }
    }
}

/// Selector trait — `RR → P2C` switch without rewrite (per RFC-003 D4).
pub trait Selector: Send + Sync {
    fn select(&self, upstreams: &[Upstream]) -> Option<Upstream>;
}

/// Round-robin — skips empty, strict counter.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Selector for RoundRobin {
    fn select(&self, upstreams: &[Upstream]) -> Option<Upstream> {
        if upstreams.is_empty() {
            return None;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed);
        Some(upstreams[idx % upstreams.len()].clone())
    }
}

/// P2C (power-of-two-choices) stub — picks two candidates via RR and chooses first (load metric placeholder).
/// Upgrade path: replace `choose` with EWMA latency comparison without changing call sites.
#[derive(Debug, Default)]
pub struct P2c {
    rr: RoundRobin,
}

impl P2c {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Selector for P2c {
    fn select(&self, upstreams: &[Upstream]) -> Option<Upstream> {
        if upstreams.is_empty() {
            return None;
        }
        if upstreams.len() == 1 {
            return Some(upstreams[0].clone());
        }
        // Two candidates via RR counter.
        let a = self.rr.next.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        let b = self.rr.next.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        // Stub: no load metric yet, pick `a` deterministically. Real impl compares EWMA.
        let chosen = a;
        let _ = b;
        Some(upstreams[chosen].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ups(n: usize) -> Vec<Upstream> {
        (0..n)
            .map(|i| Upstream::new(format!("up{i}"), format!("http://127.0.0.1:300{i}"), 1))
            .collect()
    }

    #[test]
    fn rr_cycles() {
        let rr = RoundRobin::new();
        let u = ups(3);
        assert_eq!(rr.select(&u).unwrap().name, "up0");
        assert_eq!(rr.select(&u).unwrap().name, "up1");
        assert_eq!(rr.select(&u).unwrap().name, "up2");
        assert_eq!(rr.select(&u).unwrap().name, "up0");
    }

    #[test]
    fn rr_empty_none() {
        let rr = RoundRobin::new();
        assert!(rr.select(&[]).is_none());
    }

    #[test]
    fn p2c_single() {
        let p2c = P2c::new();
        let u = ups(1);
        assert_eq!(p2c.select(&u).unwrap().name, "up0");
    }

    #[test]
    fn p2c_two_candidates() {
        let p2c = P2c::new();
        let u = ups(2);
        // Deterministic stub picks a
        assert!(p2c.select(&u).is_some());
    }
}
