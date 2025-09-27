//! Authority Chain Data Structures
//!
//! Core key types and hierarchy relationships implementing the X→M→R→I→D
//! authority chain with cryptographic key material handling.

use std::fmt;
use std::path::{Path, PathBuf};
use hub::time_ext::chrono::{DateTime, Utc};
use hub::data_ext::serde::{Deserialize, Serialize};

use crate::ignite::error::{IgniteError, Result};

//corrective
// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// pub enum KeyType {
//     Skull,
//     Master,
//     Repo,
//     Ignition,
//     Distro,
// }

// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct KeyFingerprint(String);

// impl KeyFingerprint {
//     pub fn new(value: impl Into<String>) -> Self {
//         Self(value.into())
//     }

//     pub fn as_str(&self) -> &str {
//         &self.0
//     }
// }

// #[derive(Debug, Default)]
// pub struct AuthorityChain;

// impl AuthorityChain {
//     pub fn new() -> Self {
//         Self
//     }
// }


/// Key types in the authority hierarchy (X→M→R→I→D)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum KeyType {
    /// X - Skull Key (Ultimate Authority)
    Skull,
    /// M - Master Key (Global Authority)
    Master,
    /// R - Repository Key (Local Authority)
    Repo,
    /// I - Ignition Key (Authority Bridge)
    Ignition,
    /// D - Distro Key (Distributed Access)
    Distro,
}

impl KeyType {
    pub fn description(&self) -> &'static str {
        match self {
            KeyType::Skull => "Skull Key (Ultimate Authority - Emergency Recovery)",
            KeyType::Master => "Master Key (Global Authority - System Administration)",
            KeyType::Repo => "Repository Key (Local Authority - Repository Management)",
            KeyType::Ignition => "Ignition Key (Authority Bridge - Automation Access)",
            KeyType::Distro => "Distro Key (Distributed Access - Third Party Access)",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "skull" | "x" => Ok(KeyType::Skull),
            "master" | "m" => Ok(KeyType::Master),
            "repo" | "repository" | "r" => Ok(KeyType::Repo),
            "ignition" | "i" => Ok(KeyType::Ignition),
            "distro" | "distribution" | "d" => Ok(KeyType::Distro),
            _ => Err(IgniteError::InvalidOperation {
                operation: "parse_key_type".to_string(),
                reason: format!("Unknown key type: {}", s),
            }),
        }
    }

    pub fn can_control(&self, child: KeyType) -> bool {
        matches!(
            (self, child),
            (KeyType::Skull, KeyType::Master)
                | (KeyType::Master, KeyType::Repo)
                | (KeyType::Repo, KeyType::Ignition)
                | (KeyType::Ignition, KeyType::Distro)
        )
    }

    pub fn parent_type(&self) -> Option<KeyType> {
        match self {
            KeyType::Skull => None,
            KeyType::Master => Some(KeyType::Skull),
            KeyType::Repo => Some(KeyType::Master),
            KeyType::Ignition => Some(KeyType::Repo),
            KeyType::Distro => Some(KeyType::Ignition),
        }
    }

    pub fn child_types(&self) -> Vec<KeyType> {
        match self {
            KeyType::Skull => vec![KeyType::Master],
            KeyType::Master => vec![KeyType::Repo],
            KeyType::Repo => vec![KeyType::Ignition],
            KeyType::Ignition => vec![KeyType::Distro],
            KeyType::Distro => vec![],
        }
    }

    pub fn is_ignition_key(&self) -> bool {
        matches!(self, KeyType::Skull | KeyType::Ignition | KeyType::Distro)
    }
}

impl From<KeyType> for String {
    fn from(kt: KeyType) -> String {
        match kt {
            KeyType::Skull => "skull".to_string(),
            KeyType::Master => "master".to_string(),
            KeyType::Repo => "repo".to_string(),
            KeyType::Ignition => "ignition".to_string(),
            KeyType::Distro => "distro".to_string(),
        }
    }
}

impl TryFrom<String> for KeyType {
    type Error = IgniteError;

    fn try_from(s: String) -> Result<Self> {
        KeyType::from_str(&s)
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(*self))
    }
}

/// Cryptographic fingerprint for key identification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct KeyFingerprint {
    fingerprint: String,
    algorithm: String,
}

impl From<KeyFingerprint> for String {
    fn from(fp: KeyFingerprint) -> String {
        format!("{}:{}", fp.algorithm, fp.fingerprint)
    }
}

impl TryFrom<String> for KeyFingerprint {
    type Error = IgniteError;

    fn try_from(s: String) -> Result<Self> {
        KeyFingerprint::from_string(&s)
    }
}

impl KeyFingerprint {
    /// Create new fingerprint from key material using SHA256
    pub fn from_key_material(key_material: &[u8]) -> Result<Self> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(key_material);
        let hash = hasher.finalize();

        Ok(KeyFingerprint {
            fingerprint: format!("{:x}", hash),
            algorithm: "SHA256".to_string(),
        })
    }

    /// Create fingerprint from file
    pub fn from_file(path: &Path) -> Result<Self> {
        let key_material = std::fs::read(path)
            .map_err(|e| IgniteError::io_error("read_key_file", path.to_path_buf(), e))?;
        Self::from_key_material(&key_material)
    }

    /// Get hex representation of fingerprint
    pub fn hex(&self) -> &str {
        &self.fingerprint
    }

    /// Get short representation (first 8 chars) for display
    pub fn short(&self) -> String {
        self.fingerprint.chars().take(8).collect()
    }

    /// Parse from string in format "ALGO:hexstring" (e.g., "SHA256:a1b2c3d4...")
    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(IgniteError::InvalidKey {
                reason: format!("Invalid fingerprint format: {}", s),
            });
        }

        Ok(KeyFingerprint {
            algorithm: parts[0].to_string(),
            fingerprint: parts[1].to_string(),
        })
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.fingerprint)
    }
}

/// Key format variants supported by Ignite
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KeyFormat {
    /// Age format (via cage library, NOT rage)
    Age,
    /// Ed25519 raw format (for authority proofs)
    Ed25519,
}

/// Cryptographic key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    public_key: Vec<u8>,
    private_key: Option<Vec<u8>>,
    key_format: KeyFormat,
}

impl KeyMaterial {
    pub fn new(public_key: Vec<u8>, private_key: Option<Vec<u8>>, format: KeyFormat) -> Self {
        Self {
            public_key,
            private_key,
            key_format: format,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_deref()
    }

    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    pub fn format(&self) -> KeyFormat {
        self.key_format
    }

    pub fn fingerprint(&self) -> Result<KeyFingerprint> {
        KeyFingerprint::from_key_material(&self.public_key)
    }
}

/// Metadata associated with authority keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub creation_time: DateTime<Utc>,
    pub creator: String,
    pub description: String,
    pub expiration: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

impl Default for KeyMetadata {
    fn default() -> Self {
        Self {
            creation_time: Utc::now(),
            creator: "unknown".to_string(),
            description: "Authority key".to_string(),
            expiration: None,
            last_used: None,
            usage_count: 0,
        }
    }
}

/// Authority key with metadata and relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityKey {
    key_material: KeyMaterial,
    key_type: KeyType,
    fingerprint: KeyFingerprint,
    key_path: Option<PathBuf>,
    metadata: KeyMetadata,
    /// Fingerprints of keys this key has authority over
    children: Vec<KeyFingerprint>,
}

impl AuthorityKey {
    pub fn new(
        key_material: KeyMaterial,
        key_type: KeyType,
        key_path: Option<PathBuf>,
        metadata: Option<KeyMetadata>,
    ) -> Result<Self> {
        let fingerprint = key_material.fingerprint()?;

        Ok(Self {
            key_material,
            key_type,
            fingerprint,
            key_path,
            metadata: metadata.unwrap_or_default(),
            children: Vec::new(),
        })
    }

    pub fn fingerprint(&self) -> &KeyFingerprint {
        &self.fingerprint
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }

    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    pub fn children(&self) -> &[KeyFingerprint] {
        &self.children
    }

    pub fn add_child(&mut self, child_fp: KeyFingerprint) -> Result<()> {
        if self.children.contains(&child_fp) {
            return Err(IgniteError::InvalidOperation {
                operation: "add_child".to_string(),
                reason: "Child fingerprint already exists".to_string(),
            });
        }
        self.children.push(child_fp);
        Ok(())
    }

    pub fn can_control(&self, child_type: KeyType) -> bool {
        self.key_type.can_control(child_type)
    }

    pub fn key_path(&self) -> Option<&Path> {
        self.key_path.as_deref()
    }

    pub fn set_key_path(&mut self, path: PathBuf) {
        self.key_path = Some(path);
    }

    /// Save this key to vault storage
    pub fn save(&mut self) -> Result<()> {
        // Import storage at call site to avoid circular dependency
        use crate::ignite::authority::storage;

        let path = storage::save_key(self)?;
        self.key_path = Some(path);
        Ok(())
    }

    /// Load key from vault storage
    pub fn load(key_type: KeyType, fingerprint: &KeyFingerprint) -> Result<Self> {
        use crate::ignite::authority::storage;
        storage::load_key(key_type, fingerprint)
    }
}

// TODO: Implement AuthorityChain struct to manage the full X→M→R→I→D hierarchy
// TODO: Implement chain validation logic

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, SecretKey};
    use hub::random_ext::rand::{rng, Rng};

    fn create_test_key_material() -> KeyMaterial {
        let mut random = rng();
        let secret_bytes: [u8; 32] = random.random();
        let secret_key = SecretKey::from(secret_bytes);
        let signing_key = SigningKey::from(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_key = Some(signing_key.to_bytes().to_vec());

        KeyMaterial::new(public_key, private_key, KeyFormat::Ed25519)
    }

    #[test]
    fn test_key_type_hierarchy() {
        // Test parent relationships
        assert_eq!(KeyType::Master.parent_type(), Some(KeyType::Skull));
        assert_eq!(KeyType::Repo.parent_type(), Some(KeyType::Master));
        assert_eq!(KeyType::Ignition.parent_type(), Some(KeyType::Repo));
        assert_eq!(KeyType::Distro.parent_type(), Some(KeyType::Ignition));
        assert_eq!(KeyType::Skull.parent_type(), None);

        // Test control relationships
        assert!(KeyType::Skull.can_control(KeyType::Master));
        assert!(KeyType::Master.can_control(KeyType::Repo));
        assert!(KeyType::Repo.can_control(KeyType::Ignition));
        assert!(KeyType::Ignition.can_control(KeyType::Distro));

        // Test invalid control relationships
        assert!(!KeyType::Master.can_control(KeyType::Skull));
        assert!(!KeyType::Distro.can_control(KeyType::Ignition));
        assert!(!KeyType::Skull.can_control(KeyType::Repo)); // Skip levels
    }

    #[test]
    fn test_key_type_parsing() {
        assert_eq!(KeyType::from_str("skull").unwrap(), KeyType::Skull);
        assert_eq!(KeyType::from_str("x").unwrap(), KeyType::Skull);
        assert_eq!(KeyType::from_str("master").unwrap(), KeyType::Master);
        assert_eq!(KeyType::from_str("m").unwrap(), KeyType::Master);
        assert_eq!(KeyType::from_str("repo").unwrap(), KeyType::Repo);
        assert_eq!(KeyType::from_str("repository").unwrap(), KeyType::Repo);
        assert_eq!(KeyType::from_str("ignition").unwrap(), KeyType::Ignition);
        assert_eq!(KeyType::from_str("distro").unwrap(), KeyType::Distro);

        assert!(KeyType::from_str("invalid").is_err());
    }

    #[test]
    fn test_key_fingerprint_generation() {
        let key_material = create_test_key_material();
        let fingerprint1 = key_material.fingerprint().unwrap();
        let fingerprint2 = key_material.fingerprint().unwrap();

        // Same key material should produce same fingerprint
        assert_eq!(fingerprint1.hex(), fingerprint2.hex());
        assert!(!fingerprint1.hex().is_empty());
        assert_eq!(fingerprint1.short().len(), 8);
    }

    #[test]
    fn test_key_fingerprint_parsing() {
        let fp_str = "SHA256:a1b2c3d4";
        let fingerprint = KeyFingerprint::from_string(fp_str).unwrap();
        assert_eq!(fingerprint.hex(), "a1b2c3d4");

        // Invalid format should error
        assert!(KeyFingerprint::from_string("invalid").is_err());
    }

    #[test]
    fn test_authority_key_creation() {
        let key_material = create_test_key_material();
        let authority_key = AuthorityKey::new(
            key_material,
            KeyType::Master,
            None,
            None,
        ).unwrap();

        assert_eq!(authority_key.key_type(), KeyType::Master);
        assert!(authority_key.children().is_empty());
        assert!(authority_key.can_control(KeyType::Repo));
        assert!(!authority_key.can_control(KeyType::Skull));
    }

    #[test]
    fn test_authority_key_children() {
        let key_material = create_test_key_material();
        let mut authority_key = AuthorityKey::new(
            key_material,
            KeyType::Master,
            None,
            None,
        ).unwrap();

        let child_fp = KeyFingerprint::from_string("SHA256:child123").unwrap();

        // Add child
        assert!(authority_key.add_child(child_fp.clone()).is_ok());
        assert_eq!(authority_key.children().len(), 1);
        assert_eq!(authority_key.children()[0], child_fp);

        // Adding same child should error
        assert!(authority_key.add_child(child_fp).is_err());
    }

    #[test]
    fn test_ignition_key_detection() {
        assert!(KeyType::Skull.is_ignition_key());
        assert!(!KeyType::Master.is_ignition_key());
        assert!(!KeyType::Repo.is_ignition_key());
        assert!(KeyType::Ignition.is_ignition_key());
        assert!(KeyType::Distro.is_ignition_key());
    }
}
