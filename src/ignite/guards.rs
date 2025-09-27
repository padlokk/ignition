//! Guard helpers for external dependencies and environment preconditions.

use std::process::Command;

use crate::ignite::error::IgniteError;
use crate::IgniteResult;

/// Ensure the minimum external dependencies are on the PATH before we defer to cage.
pub fn ensure_age_available() -> IgniteResult<()> {
    let output = Command::new("age")
        .arg("--version")
        .output()
        .map_err(|e| IgniteError::MissingDependency {
            binary: "age",
            context: format!("failed to spawn `age`: {}", e),
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(IgniteError::MissingDependency {
        binary: "age",
        context: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}
