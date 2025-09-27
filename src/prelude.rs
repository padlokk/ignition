//! Ignite public prelude.
//!
//! Commonly used types and traits for Ignite users.

pub use crate::ignite::error::{IgniteError, Result};
pub use crate::ignite::authority::{
    KeyType, KeyFingerprint, KeyMaterial, KeyFormat,
    AuthorityKey, KeyMetadata,
};


//corrective
// pub use crate::ignite::error::IgniteError;
// pub use crate::IgniteResult;

// pub use crate::ignite::guards::ensure_age_available;
// pub use crate::ignite::utils::{config_root, data_root};
