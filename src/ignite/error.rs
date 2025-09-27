use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

/// Ignite-specific error type. Expand with additional variants as the
/// authority engine is implemented.
#[derive(Debug)]
pub enum IgniteError {
    /// Raised when a required external dependency is missing (e.g. `age`).
    MissingDependency {
        binary: &'static str,
        context: String,
    },
    /// Placeholder for yet-to-be-defined errors.
    NotReady(&'static str),
    /// Invalid operation or authority relationship
    InvalidOperation {
        operation: String,
        reason: String,
    },
    /// I/O error during file operations
    IoError {
        operation: String,
        path: PathBuf,
        source: std::io::Error,
    },
    /// Cryptographic operation failed
    CryptoError {
        operation: String,
        reason: String,
    },
    /// Key validation failed
    InvalidKey {
        reason: String,
    },
}

impl Display for IgniteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IgniteError::MissingDependency { binary, context } => {
                write!(f, "missing dependency `{}`: {}", binary, context)
            }
            IgniteError::NotReady(msg) => write!(f, "not implemented: {}", msg),
            IgniteError::InvalidOperation { operation, reason } => {
                write!(f, "invalid operation '{}': {}", operation, reason)
            }
            IgniteError::IoError { operation, path, source } => {
                write!(f, "I/O error during '{}' on {:?}: {}", operation, path, source)
            }
            IgniteError::CryptoError { operation, reason } => {
                write!(f, "crypto error in '{}': {}", operation, reason)
            }
            IgniteError::InvalidKey { reason } => {
                write!(f, "invalid key: {}", reason)
            }
        }
    }
}

impl Error for IgniteError {}

pub type Result<T> = std::result::Result<T, IgniteError>;

impl IgniteError {
    pub fn io_error(operation: impl Into<String>, path: PathBuf, source: std::io::Error) -> Self {
        Self::IoError {
            operation: operation.into(),
            path,
            source,
        }
    }

    pub fn crypto_error(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CryptoError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
}
