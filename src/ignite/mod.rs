//! Ignite module orchestrator.
//!
//! Re-exports curated public surface per MODULE_SPEC. Internal helpers live in
//! submodules; adapters/integrations will be added as functionality lands.

pub mod error;
pub mod utils;
pub mod guards;
pub mod authority;

pub use error::{IgniteError, Result};
