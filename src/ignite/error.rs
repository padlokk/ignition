use std::error::Error;
use std::fmt::{self, Display, Formatter};

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
}

impl Display for IgniteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IgniteError::MissingDependency { binary, context } => {
                write!(f, "missing dependency `{}`: {}", binary, context)
            }
            IgniteError::NotReady(msg) => write!(f, "not implemented: {}", msg),
        }
    }
}

impl Error for IgniteError {}
