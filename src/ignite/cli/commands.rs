//! Ignite command handlers.
//!
//! NOTE: Current CLI implementation lives in src/bin/cli_ignite.rs using clap.
//! This module exists as a placeholder for future command surface delegation
//! following RSB module patterns. When the CLI matures, command handler logic
//! should be extracted here for testability and reuse.
//!
//! Current commands (implemented in bin/cli_ignite.rs):
//! - create: Create new authority keys with optional parent proofs
//! - list: List authority keys by type
//! - status: Show authority chain status
//! - verify: Verify proof or manifest files

pub struct IgniteCommands;

impl IgniteCommands {
    pub fn new() -> Self {
        Self
    }
}
