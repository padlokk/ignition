//! Storage-specific error definitions.

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    InvalidFormat(String),
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}
