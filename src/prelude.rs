//! Ignite public prelude.
//!
//! Commonly used types and traits for Ignite users.

pub use crate::ignite::authority::{
    AuthorityKey, KeyFingerprint, KeyFormat, KeyMaterial, KeyMetadata, KeyType,
};
pub use crate::ignite::error::{IgniteError, Result};

//corrective
// pub use crate::ignite::error::IgniteError;
// pub use crate::IgniteResult;

// pub use crate::ignite::guards::ensure_age_available;
// pub use crate::ignite::utils::{config_root, data_root};
