//! Core types and traits for xproxy.
//!
//! No major implementation — boilerplate only.

pub mod config;
pub mod error;
pub mod net;
pub mod orchestrator;

pub use config::{Config, Mode};
pub use error::{Error, Result};
pub use orchestrator::{ModeState, Orchestrator, SharedModeState};

/// Proxy mode discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    Forward,
    Reverse,
}

/// Minimal proxy trait — implementors to provide `name` only for now.
pub trait Proxy: Send + Sync {
    fn mode(&self) -> ProxyMode;
    fn name(&self) -> &'static str;
}
