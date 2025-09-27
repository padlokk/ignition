//! Ignite library entry point.
//!
//! Module structure follows the RSB MODULE_SPEC: each module owns its
//! orchestrator (`mod.rs`), helper namespaces (`utils.rs`, `macros.rs`),
//! and typed errors (`error.rs`).

pub mod ignite;
pub mod prelude;
pub mod prelude_dev;

pub use ignite::error::IgniteError;
pub type IgniteResult<T> = Result<T, IgniteError>;
