//! Authority chain management for Ignite.
//!
//! Implements the X→M→R→I→D authority hierarchy with cryptographic proofs,
//! manifests, and key lifecycle management.

pub mod chain;
pub mod manifests;
pub mod proofs;
pub mod storage;

pub use chain::{AuthorityKey, KeyFingerprint, KeyFormat, KeyMaterial, KeyMetadata, KeyType};
pub use manifests::{AffectedKeyManifest, ManifestChild, ManifestEvent};
pub use proofs::{AuthorityClaim, ProofBundle, SubjectReceipt};
