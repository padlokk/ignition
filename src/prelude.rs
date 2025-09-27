//! Ignite public prelude.
//!
//! Commonly used types and traits for Ignite users.

pub use crate::ignite::error::{IgniteError, Result};
pub use crate::ignite::authority::{
    KeyType, KeyFingerprint, KeyMaterial, KeyFormat,
    AuthorityKey, KeyMetadata,
};