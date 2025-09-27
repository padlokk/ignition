//! Storage adapters (stubs) following the cross-module integration pattern.

use std::path::PathBuf;

use super::error::StorageError;

pub struct FilesystemVault;

impl FilesystemVault {
    pub fn new(_root: PathBuf) -> Result<Self, StorageError> {
        Ok(Self)
    }
}
