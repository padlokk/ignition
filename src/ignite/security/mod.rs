//! Security orchestration.
//!
//! Centralizes security policy enforcement including:
//! - Passphrase requirements and validation
//! - Danger-mode guards for destructive operations
//! - Dual-control requirements for sensitive keys
//! - Security audit integration
//!
//! See `policy` module for the modular policy engine implementation.

pub mod policy;

pub use policy::{ExpirationPolicy, PassphraseStrengthPolicy, Policy, PolicyEngine};
