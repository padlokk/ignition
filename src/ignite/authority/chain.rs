//! Authority Chain Data Structures
//!
//! Core key types and hierarchy relationships implementing the X→M→R→I→D
//! authority chain with cryptographic key material handling.

use hub::data_ext::serde::{Deserialize, Serialize};
use hub::time_ext::chrono::{DateTime, Utc};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::ignite::error::{IgniteError, Result};

/// Key types in the authority hierarchy (X→M→R→I→D)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        use sha2::{Digest, Sha256};

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

impl KeyMetadata {
    pub fn set_expiration(&mut self, expiration: Option<DateTime<Utc>>) {
        self.expiration = expiration;
    }

    pub fn expiration(&self) -> Option<DateTime<Utc>> {
        self.expiration
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

    pub fn metadata_mut(&mut self) -> &mut KeyMetadata {
        &mut self.metadata
    }

    /// Returns true if the key has an expiration timestamp in the past.
    pub fn is_expired(&self) -> bool {
        self.metadata
            .expiration
            .map(|deadline| hub::time_ext::chrono::Utc::now() > deadline)
            .unwrap_or(false)
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

/// Authority chain managing key relationships and hierarchy
///
/// The AuthorityChain maintains a registry of all authority keys and their
/// parent-child relationships, enforcing the X→M→R→I→D hierarchy rules.
#[derive(Debug, Clone)]
pub struct AuthorityChain {
    keys: std::collections::HashMap<KeyFingerprint, AuthorityKey>,
    relationships: std::collections::HashMap<KeyFingerprint, Vec<KeyFingerprint>>, // parent -> children
    reverse_relationships: std::collections::HashMap<KeyFingerprint, KeyFingerprint>, // child -> parent
}

impl AuthorityChain {
    /// Create new empty authority chain
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            relationships: std::collections::HashMap::new(),
            reverse_relationships: std::collections::HashMap::new(),
        }
    }

    /// Add key to authority chain
    pub fn add_key(&mut self, key: AuthorityKey) -> Result<()> {
        let fingerprint = key.fingerprint().clone();

        if self.keys.contains_key(&fingerprint) {
            return Err(IgniteError::InvalidOperation {
                operation: "add_key".to_string(),
                reason: format!("Key already exists: {}", fingerprint),
            });
        }

        self.keys.insert(fingerprint, key);
        Ok(())
    }

    /// Get key by fingerprint
    pub fn get_key(&self, fingerprint: &KeyFingerprint) -> Option<&AuthorityKey> {
        self.keys.get(fingerprint)
    }

    /// Get mutable key by fingerprint
    pub fn get_key_mut(&mut self, fingerprint: &KeyFingerprint) -> Option<&mut AuthorityKey> {
        self.keys.get_mut(fingerprint)
    }

    /// Add authority relationship between parent and child keys
    pub fn add_authority_relationship(
        &mut self,
        parent: &KeyFingerprint,
        child: &KeyFingerprint,
    ) -> Result<()> {
        let parent_key = self
            .get_key(parent)
            .ok_or_else(|| IgniteError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!("Parent key not found: {}", parent),
            })?;
        let child_key = self
            .get_key(child)
            .ok_or_else(|| IgniteError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!("Child key not found: {}", child),
            })?;

        if !parent_key.key_type().can_control(child_key.key_type()) {
            return Err(IgniteError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!(
                    "Invalid authority relationship: {} cannot control {}",
                    parent_key.key_type().description(),
                    child_key.key_type().description()
                ),
            });
        }

        if let Some(existing_parent) = self.reverse_relationships.get(child) {
            if existing_parent != parent {
                return Err(IgniteError::InvalidOperation {
                    operation: "add_authority".to_string(),
                    reason: format!(
                        "Child key {} already has parent {}",
                        child.short(),
                        existing_parent.short()
                    ),
                });
            }
        }

        if self
            .relationships
            .get(parent)
            .map(|children| children.contains(child))
            .unwrap_or(false)
        {
            return Err(IgniteError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!(
                    "Relationship already exists: {} -> {}",
                    parent.short(),
                    child.short()
                ),
            });
        }

        self.relationships
            .entry(parent.clone())
            .or_insert_with(Vec::new)
            .push(child.clone());
        self.reverse_relationships
            .insert(child.clone(), parent.clone());

        if let Some(parent_key) = self.get_key_mut(parent) {
            parent_key.add_child(child.clone())?;
        }

        Ok(())
    }

    /// Check if parent has authority over child
    pub fn has_authority(&self, parent: &KeyFingerprint, child: &KeyFingerprint) -> bool {
        if let Some(children) = self.relationships.get(parent) {
            children.contains(child)
        } else {
            false
        }
    }

    /// Check if child is subject to parent
    pub fn is_subject_to(&self, child: &KeyFingerprint, parent: &KeyFingerprint) -> bool {
        if let Some(actual_parent) = self.reverse_relationships.get(child) {
            actual_parent == parent
        } else {
            false
        }
    }

    /// Get all child keys for a parent
    pub fn get_children(&self, parent: &KeyFingerprint) -> Vec<&AuthorityKey> {
        if let Some(child_fingerprints) = self.relationships.get(parent) {
            child_fingerprints
                .iter()
                .filter_map(|fp| self.get_key(fp))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get parent key for a child
    pub fn get_parent(&self, child: &KeyFingerprint) -> Option<&AuthorityKey> {
        self.reverse_relationships
            .get(child)
            .and_then(|parent_fp| self.get_key(parent_fp))
    }

    /// Get all keys of a specific type
    pub fn get_keys_by_type(&self, key_type: KeyType) -> Vec<&AuthorityKey> {
        self.keys
            .values()
            .filter(|key| key.key_type() == key_type)
            .collect()
    }

    /// Find dependent keys that would be affected by key rotation/revocation
    ///
    /// This performs a breadth-first traversal to find all descendant keys.
    /// Critical for generating affected-key manifests during rotate/revoke operations.
    pub fn find_dependent_keys(&self, target: &KeyFingerprint) -> Result<Vec<AuthorityKey>> {
        let mut dependents = Vec::new();
        let mut to_process = vec![target.clone()];

        while let Some(current) = to_process.pop() {
            if let Some(children) = self.relationships.get(&current) {
                for child_fp in children {
                    if let Some(child_key) = self.get_key(child_fp) {
                        dependents.push(child_key.clone());
                        to_process.push(child_fp.clone());
                    }
                }
            }
        }

        Ok(dependents)
    }

    /// Validate entire authority chain integrity
    ///
    /// Checks for:
    /// - Authority cycles (which would violate the DAG structure)
    /// - Hierarchy rule violations (e.g., Master controlling Distro directly)
    /// - Orphaned keys in relationship maps
    pub fn validate_integrity(&self) -> Result<()> {
        for (parent_fp, children) in &self.relationships {
            for child_fp in children {
                if self.has_authority_path(child_fp, parent_fp) {
                    return Err(IgniteError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!("Authority cycle detected: {} -> {}", parent_fp, child_fp),
                    });
                }
            }
        }

        for (parent_fp, children) in &self.relationships {
            let parent_key =
                self.get_key(parent_fp)
                    .ok_or_else(|| IgniteError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!("Missing parent key: {}", parent_fp),
                    })?;

            for child_fp in children {
                let child_key =
                    self.get_key(child_fp)
                        .ok_or_else(|| IgniteError::InvalidOperation {
                            operation: "validate_integrity".to_string(),
                            reason: format!("Missing child key: {}", child_fp),
                        })?;

                if !parent_key.key_type().can_control(child_key.key_type()) {
                    return Err(IgniteError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!(
                            "Invalid hierarchy: {} cannot control {}",
                            parent_key.key_type().description(),
                            child_key.key_type().description()
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Check if there's an authority path from start to end (for cycle detection)
    fn has_authority_path(&self, start: &KeyFingerprint, end: &KeyFingerprint) -> bool {
        if start == end {
            return true;
        }

        if let Some(children) = self.relationships.get(start) {
            for child in children {
                if self.has_authority_path(child, end) {
                    return true;
                }
            }
        }

        false
    }

    /// Get total number of keys in chain
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for AuthorityChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SecretKey, SigningKey};
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
        let authority_key = AuthorityKey::new(key_material, KeyType::Master, None, None).unwrap();

        assert_eq!(authority_key.key_type(), KeyType::Master);
        assert!(authority_key.children().is_empty());
        assert!(authority_key.can_control(KeyType::Repo));
        assert!(!authority_key.can_control(KeyType::Skull));
    }

    #[test]
    fn test_authority_key_children() {
        let key_material = create_test_key_material();
        let mut authority_key =
            AuthorityKey::new(key_material, KeyType::Master, None, None).unwrap();

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

    #[test]
    fn test_authority_chain_basic() {
        let chain = AuthorityChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_authority_chain_add_key() {
        let mut chain = AuthorityChain::new();

        let key_material = create_test_key_material();
        let key = AuthorityKey::new(key_material, KeyType::Master, None, None).unwrap();
        let fingerprint = key.fingerprint().clone();

        assert!(chain.add_key(key).is_ok());
        assert_eq!(chain.len(), 1);
        assert!(chain.get_key(&fingerprint).is_some());
    }

    #[test]
    fn test_authority_chain_add_relationship() {
        let mut chain = AuthorityChain::new();

        let skull_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let skull_fp = skull_key.fingerprint().clone();

        let master_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master_fp = master_key.fingerprint().clone();

        chain.add_key(skull_key).unwrap();
        chain.add_key(master_key).unwrap();

        assert!(chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .is_ok());
        assert!(chain.has_authority(&skull_fp, &master_fp));
        assert!(chain.is_subject_to(&master_fp, &skull_fp));
    }

    #[test]
    fn test_authority_chain_duplicate_relationship_rejected() {
        let mut chain = AuthorityChain::new();

        let skull_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let skull_fp = skull_key.fingerprint().clone();

        let master_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master_fp = master_key.fingerprint().clone();

        chain.add_key(skull_key).unwrap();
        chain.add_key(master_key).unwrap();

        assert!(chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .is_ok());

        let result = chain.add_authority_relationship(&skull_fp, &master_fp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_authority_chain_parent_reassignment_rejected() {
        let mut chain = AuthorityChain::new();

        let skull1 =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let skull1_fp = skull1.fingerprint().clone();

        let skull2 =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let skull2_fp = skull2.fingerprint().clone();

        let master_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master_fp = master_key.fingerprint().clone();

        chain.add_key(skull1).unwrap();
        chain.add_key(skull2).unwrap();
        chain.add_key(master_key).unwrap();

        assert!(chain
            .add_authority_relationship(&skull1_fp, &master_fp)
            .is_ok());

        let result = chain.add_authority_relationship(&skull2_fp, &master_fp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already has parent"));
    }

    #[test]
    fn test_authority_chain_invalid_hierarchy_rejected() {
        let mut chain = AuthorityChain::new();

        let master_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master_fp = master_key.fingerprint().clone();

        let skull_key =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let skull_fp = skull_key.fingerprint().clone();

        chain.add_key(master_key).unwrap();
        chain.add_key(skull_key).unwrap();

        let result = chain.add_authority_relationship(&master_fp, &skull_fp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot control"));
    }

    #[test]
    fn test_authority_chain_hierarchy_levels() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let repo =
            AuthorityKey::new(create_test_key_material(), KeyType::Repo, None, None).unwrap();
        let ignition =
            AuthorityKey::new(create_test_key_material(), KeyType::Ignition, None, None).unwrap();
        let distro =
            AuthorityKey::new(create_test_key_material(), KeyType::Distro, None, None).unwrap();

        let skull_fp = skull.fingerprint().clone();
        let master_fp = master.fingerprint().clone();
        let repo_fp = repo.fingerprint().clone();
        let ignition_fp = ignition.fingerprint().clone();
        let distro_fp = distro.fingerprint().clone();

        chain.add_key(skull).unwrap();
        chain.add_key(master).unwrap();
        chain.add_key(repo).unwrap();
        chain.add_key(ignition).unwrap();
        chain.add_key(distro).unwrap();

        assert!(chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .is_ok());
        assert!(chain
            .add_authority_relationship(&master_fp, &repo_fp)
            .is_ok());
        assert!(chain
            .add_authority_relationship(&repo_fp, &ignition_fp)
            .is_ok());
        assert!(chain
            .add_authority_relationship(&ignition_fp, &distro_fp)
            .is_ok());

        assert!(chain.has_authority(&skull_fp, &master_fp));
        assert!(chain.has_authority(&master_fp, &repo_fp));
        assert!(chain.has_authority(&repo_fp, &ignition_fp));
        assert!(chain.has_authority(&ignition_fp, &distro_fp));

        assert!(!chain.has_authority(&distro_fp, &ignition_fp));
    }

    #[test]
    fn test_authority_chain_get_children() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master1 =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master2 =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();

        let skull_fp = skull.fingerprint().clone();
        let master1_fp = master1.fingerprint().clone();
        let master2_fp = master2.fingerprint().clone();

        chain.add_key(skull).unwrap();
        chain.add_key(master1).unwrap();
        chain.add_key(master2).unwrap();

        chain
            .add_authority_relationship(&skull_fp, &master1_fp)
            .unwrap();
        chain
            .add_authority_relationship(&skull_fp, &master2_fp)
            .unwrap();

        let children = chain.get_children(&skull_fp);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_authority_chain_get_parent() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();

        let skull_fp = skull.fingerprint().clone();
        let master_fp = master.fingerprint().clone();

        chain.add_key(skull).unwrap();
        chain.add_key(master).unwrap();

        chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .unwrap();

        let parent = chain.get_parent(&master_fp);
        assert!(parent.is_some());
        assert_eq!(parent.unwrap().fingerprint(), &skull_fp);

        assert!(chain.get_parent(&skull_fp).is_none());
    }

    #[test]
    fn test_authority_chain_find_dependent_keys() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let repo =
            AuthorityKey::new(create_test_key_material(), KeyType::Repo, None, None).unwrap();

        let skull_fp = skull.fingerprint().clone();
        let master_fp = master.fingerprint().clone();
        let repo_fp = repo.fingerprint().clone();

        chain.add_key(skull).unwrap();
        chain.add_key(master).unwrap();
        chain.add_key(repo).unwrap();

        chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .unwrap();
        chain
            .add_authority_relationship(&master_fp, &repo_fp)
            .unwrap();

        let dependents = chain.find_dependent_keys(&skull_fp).unwrap();
        assert_eq!(dependents.len(), 2);

        let dependent_fps: Vec<_> = dependents.iter().map(|k| k.fingerprint()).collect();
        assert!(dependent_fps.contains(&&master_fp));
        assert!(dependent_fps.contains(&&repo_fp));
    }

    #[test]
    fn test_authority_chain_validate_integrity_valid() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();

        let skull_fp = skull.fingerprint().clone();
        let master_fp = master.fingerprint().clone();

        chain.add_key(skull).unwrap();
        chain.add_key(master).unwrap();
        chain
            .add_authority_relationship(&skull_fp, &master_fp)
            .unwrap();

        assert!(chain.validate_integrity().is_ok());
    }

    #[test]
    fn test_authority_chain_get_keys_by_type() {
        let mut chain = AuthorityChain::new();

        let skull =
            AuthorityKey::new(create_test_key_material(), KeyType::Skull, None, None).unwrap();
        let master1 =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();
        let master2 =
            AuthorityKey::new(create_test_key_material(), KeyType::Master, None, None).unwrap();

        chain.add_key(skull).unwrap();
        chain.add_key(master1).unwrap();
        chain.add_key(master2).unwrap();

        let masters = chain.get_keys_by_type(KeyType::Master);
        assert_eq!(masters.len(), 2);

        let skulls = chain.get_keys_by_type(KeyType::Skull);
        assert_eq!(skulls.len(), 1);
    }
}
