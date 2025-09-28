//! Ignite module orchestrator.
//!
//! Re-exports curated public surface per MODULE_SPEC. Internal helpers live in
//! submodules; adapters/integrations will be added as functionality lands.

pub mod error;
pub mod guards;
pub mod macros;
pub mod prelude;
pub mod prelude_dev;
pub mod utils;

pub mod authority;
pub mod cli;
pub mod logging;
pub mod security;

pub use error::{IgniteError, Result};
