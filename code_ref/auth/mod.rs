//! Authority Chain Management System
//!
//! Complete implementation of X->M->R->I->D authority chain with ignition key protocol.
//! This module provides mathematical validation with cryptographic proofs for authority
//! relationships, building on proven Age automation and Lucas's authority patterns.
//!
//! Security Guardian: Edgar - Authority chain protocol implementation

pub mod chain;
pub mod ignition;
pub mod validation;
pub mod operations;
pub mod bridge;

// Re-export key types for convenience
pub use chain::{KeyType, AuthorityChain, AuthorityKey, KeyFingerprint};
pub use ignition::{IgnitionKey, PassphraseHash};
pub use validation::{AuthorityProof, SubjectProof, AuthorityLevel};
pub use operations::{AuthorityAgeKeyGenerator, GeneratedAgeKey, AuthorityAgeEncryption, EncryptionParams, EncryptionResult};

use crate::sec::cage::error::{AgeError, AgeResult};

/// Authority module version for compatibility tracking
pub const AUTHORITY_VERSION: &str = "1.0.0-pilot03";

/// Initialize authority subsystem
pub fn initialize() -> AgeResult<()> {
    // Validate dependencies and initialize subsystem
    validation::initialize_validation_engine()?;
    Ok(())
}