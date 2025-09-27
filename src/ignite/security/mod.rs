//! Security orchestration.
//!
//! Centralizes security policy enforcement including:
//! - Passphrase requirements and validation
//! - Danger-mode guards for destructive operations
//! - Dual-control requirements for sensitive keys
//! - Security audit integration
//!
//! See policy.rs for detailed policy implementation (currently stub).

pub mod policy;

pub use policy::PassphrasePolicy;
