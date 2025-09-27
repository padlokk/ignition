//! Authority Integration Bridges
//!
//! Integration bridges connecting authority chain with external systems:
//! - Age automation integration (Edgar's TTY patterns)
//! - Lucas authority pattern integration (atomic operations)
//!
//! Security Guardian: Edgar - Authority integration framework

pub mod age_integration;

pub use age_integration::{
    AuthorityAgeInterface,
    LucasAuthorityBridge,
    AuthorityAgeFactory,
};

use crate::sec::cage::error::AgeResult;

/// Initialize all bridge subsystems
pub fn initialize() -> AgeResult<()> {
    // Perform any bridge initialization required
    Ok(())
}