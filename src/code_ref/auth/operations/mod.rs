//! Authority Operations Module
//!
//! Implements the complete operations framework for X->M->R->I->D authority chain management.
//! Provides real Age encryption operations with authority validation and ignition key workflow.
//!
//! Security Guardian: Edgar - Production operations with Lucas's proven patterns

pub mod generate;
pub mod encrypt;

// Re-export main components
pub use generate::{AuthorityAgeKeyGenerator, GeneratedAgeKey};
pub use encrypt::{AuthorityAgeEncryption, EncryptionParams, EncryptionResult};