//! Ignite module orchestrator.
//!
//! Re-exports curated public surface per MODULE_SPEC. Internal helpers live in
//! submodules; adapters/integrations will be added as functionality lands.

pub mod error;
pub mod utils;
pub mod guards;
pub mod authority;

pub use error::{IgniteError, Result};


//corrective
// pub mod error;
// pub mod utils;
// pub mod guards;
// pub mod macros;
// pub mod prelude;
// pub mod prelude_dev;

// pub mod authority;
// pub mod cli;
// pub mod security;
// pub mod logging;

// pub use error::IgniteError;

pub mod chain;
pub mod proofs;
pub mod manifests;
pub mod storage;

pub use chain::{AuthorityChain, KeyFingerprint, KeyType};
