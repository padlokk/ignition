//! Authority chain management for Ignite.
//!
//! Implements the X→M→R→I→D authority hierarchy with cryptographic proofs,
//! manifests, and key lifecycle management.

pub mod chain;
pub mod proofs;
pub mod manifests;
pub mod storage;

pub use chain::{KeyType, KeyFingerprint, KeyMaterial, KeyFormat, AuthorityKey, KeyMetadata};
pub use proofs::{AuthorityClaim, SubjectReceipt, ProofBundle};
pub use manifests::{AffectedKeyManifest, ManifestEvent, ManifestChild};




//corrective AuthorityChain?
