//! Ignite prelude for common imports.
//!
//! Provides curated re-exports for typical Ignite usage.

pub use crate::ignite::authority::chain::{AuthorityKey, KeyFingerprint, KeyType};
pub use crate::ignite::authority::manifests::{AffectedKeyManifest, ManifestEvent};
pub use crate::ignite::authority::proofs::{AuthorityClaim, ProofBundle, SubjectReceipt};
pub use crate::ignite::error::{IgniteError, Result};
