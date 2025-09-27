//! Ignite prelude for common imports.
//!
//! Provides curated re-exports for typical Ignite usage.

pub use crate::ignite::error::{IgniteError, Result};
pub use crate::ignite::authority::chain::{KeyType, KeyFingerprint, AuthorityKey};
pub use crate::ignite::authority::proofs::{AuthorityClaim, SubjectReceipt, ProofBundle};
pub use crate::ignite::authority::manifests::{AffectedKeyManifest, ManifestEvent};