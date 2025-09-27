//! Authority Chain Data Structures
//!
//! Core key types and hierarchy relationships implementing the X->M->R->I->D
//! authority chain with cryptographic key material handling.
//!
//! Security Guardian: Edgar - Mathematical precision in authority relationships

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::sec::cage::error::{AgeError, AgeResult};

/// Key types in the authority hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Get human-readable description of key type
    pub fn description(&self) -> &'static str {
        match self {
            KeyType::Skull => "Skull Key (Ultimate Authority - Emergency Recovery)",
            KeyType::Master => "Master Key (Global Authority - System Administration)",
            KeyType::Repo => "Repository Key (Local Authority - Repository Management)",
            KeyType::Ignition => "Ignition Key (Authority Bridge - Automation Access)",
            KeyType::Distro => "Distro Key (Distributed Access - Third Party Access)",
        }
    }
    
    /// Get key type from string representation
    pub fn from_str(s: &str) -> AgeResult<Self> {
        match s.to_lowercase().as_str() {
            "skull" | "x" => Ok(KeyType::Skull),
            "master" | "m" => Ok(KeyType::Master),
            "repo" | "repository" | "r" => Ok(KeyType::Repo),
            "ignition" | "i" => Ok(KeyType::Ignition),
            "distro" | "distribution" | "d" => Ok(KeyType::Distro),
            _ => Err(AgeError::InvalidOperation {
                operation: "parse_key_type".to_string(),
                reason: format!("Unknown key type: {}", s),
            }),
        }
    }
    
    /// Check if this key type can have authority over another
    pub fn can_control(&self, child: KeyType) -> bool {
        matches!(
            (self, child),
            (KeyType::Skull, KeyType::Master)
                | (KeyType::Master, KeyType::Repo)
                | (KeyType::Repo, KeyType::Ignition)
                | (KeyType::Ignition, KeyType::Distro)
        )
    }
    
    /// Get the parent key type that controls this key type
    pub fn parent_type(&self) -> Option<KeyType> {
        match self {
            KeyType::Skull => None, // Skull has no parent
            KeyType::Master => Some(KeyType::Skull),
            KeyType::Repo => Some(KeyType::Master),
            KeyType::Ignition => Some(KeyType::Repo),
            KeyType::Distro => Some(KeyType::Ignition),
        }
    }
    
    /// Get child key types that this key can control
    pub fn child_types(&self) -> Vec<KeyType> {
        match self {
            KeyType::Skull => vec![KeyType::Master],
            KeyType::Master => vec![KeyType::Repo],
            KeyType::Repo => vec![KeyType::Ignition],
            KeyType::Ignition => vec![KeyType::Distro],
            KeyType::Distro => vec![], // Distro has no children
        }
    }
    
    /// Check if this key type is an ignition key (passphrase-wrapped)
    pub fn is_ignition_key(&self) -> bool {
        matches!(self, KeyType::Skull | KeyType::Ignition | KeyType::Distro)
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Skull => write!(f, "skull"),
            KeyType::Master => write!(f, "master"),
            KeyType::Repo => write!(f, "repo"),
            KeyType::Ignition => write!(f, "ignition"),
            KeyType::Distro => write!(f, "distro"),
        }
    }
}

/// Cryptographic fingerprint for key identification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyFingerprint {
    fingerprint: String,
    algorithm: String,
}

impl KeyFingerprint {
    /// Create new fingerprint from key material
    pub fn from_key_material(key_material: &[u8]) -> AgeResult<Self> {
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
    pub fn from_file(path: &Path) -> AgeResult<Self> {
        let key_material = std::fs::read(path)
            .map_err(|e| AgeError::file_error("read", path.to_path_buf(), e))?;
        Self::from_key_material(&key_material)
    }
    
    /// Get hex representation of fingerprint
    pub fn hex(&self) -> &str {
        &self.fingerprint
    }
    
    /// Get short representation (first 8 chars)
    pub fn short(&self) -> String {
        self.fingerprint.chars().take(8).collect()
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.short())
    }
}

/// Cryptographic key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    public_key: Vec<u8>,
    private_key: Option<Vec<u8>>, // None for public keys only
    key_format: KeyFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KeyFormat {
    Age,
    OpenPgp,
    Ed25519,
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(public_key: Vec<u8>, private_key: Option<Vec<u8>>, format: KeyFormat) -> Self {
        Self {
            public_key,
            private_key,
            key_format: format,
        }
    }
    
    /// Get public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    /// Get private key if available
    pub fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_deref()
    }
    
    /// Check if this is a private key
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }
    
    /// Get key format
    pub fn format(&self) -> KeyFormat {
        self.key_format
    }
    
    /// Generate fingerprint for this key
    pub fn fingerprint(&self) -> AgeResult<KeyFingerprint> {
        KeyFingerprint::from_key_material(&self.public_key)
    }
}

/// Authority key with metadata and relationships
#[derive(Debug, Clone)]
pub struct AuthorityKey {
    key_material: KeyMaterial,
    key_type: KeyType,
    fingerprint: KeyFingerprint,
    key_path: Option<PathBuf>,
    metadata: KeyMetadata,
    authority_relationships: Vec<KeyFingerprint>,
}

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

impl AuthorityKey {
    /// Create new authority key
    pub fn new(
        key_material: KeyMaterial,
        key_type: KeyType,
        key_path: Option<PathBuf>,
        metadata: Option<KeyMetadata>,
    ) -> AgeResult<Self> {
        let fingerprint = key_material.fingerprint()?;
        
        Ok(Self {
            key_material,
            key_type,
            fingerprint,
            key_path,
            metadata: metadata.unwrap_or_default(),
            authority_relationships: Vec::new(),
        })
    }
    
    /// Load authority key from file
    pub fn from_file(path: &Path, key_type: KeyType) -> AgeResult<Self> {
        let key_data = std::fs::read(path)
            .map_err(|e| AgeError::file_error("read", path.to_path_buf(), e))?;
        
        // Parse key based on format detection
        let key_material = Self::parse_key_material(&key_data)?;
        
        Self::new(key_material, key_type, Some(path.to_path_buf()), None)
    }
    
    /// Parse key material from bytes
    fn parse_key_material(data: &[u8]) -> AgeResult<KeyMaterial> {
        // Simple Age key detection (starts with "AGE-SECRET-KEY-")
        if data.starts_with(b"AGE-SECRET-KEY-") {
            Ok(KeyMaterial::new(
                data.to_vec(),
                Some(data.to_vec()),
                KeyFormat::Age,
            ))
        } else if data.starts_with(b"age1") {
            // Age public key
            Ok(KeyMaterial::new(
                data.to_vec(),
                None,
                KeyFormat::Age,
            ))
        } else {
            // Try to parse as PGP or other formats
            Err(AgeError::InvalidOperation {
                operation: "parse_key".to_string(),
                reason: "Unsupported key format".to_string(),
            })
        }
    }
    
    /// Get key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    
    /// Get fingerprint
    pub fn fingerprint(&self) -> &KeyFingerprint {
        &self.fingerprint
    }
    
    /// Get key path if available
    pub fn key_path(&self) -> Option<&Path> {
        self.key_path.as_deref()
    }
    
    /// Get key material
    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }
    
    /// Get metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }
    
    /// Update last used timestamp
    pub fn mark_used(&mut self) {
        self.metadata.last_used = Some(Utc::now());
        self.metadata.usage_count += 1;
    }
    
    /// Add authority relationship
    pub fn add_authority_relationship(&mut self, child_fingerprint: KeyFingerprint) {
        if !self.authority_relationships.contains(&child_fingerprint) {
            self.authority_relationships.push(child_fingerprint);
        }
    }
    
    /// Get authority relationships
    pub fn authority_relationships(&self) -> &[KeyFingerprint] {
        &self.authority_relationships
    }
    
    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.metadata.expiration {
            Utc::now() > expiration
        } else {
            false
        }
    }
}

/// Authority chain managing key relationships
#[derive(Debug, Clone)]
pub struct AuthorityChain {
    keys: HashMap<KeyFingerprint, AuthorityKey>,
    relationships: HashMap<KeyFingerprint, Vec<KeyFingerprint>>, // parent -> children
    reverse_relationships: HashMap<KeyFingerprint, KeyFingerprint>, // child -> parent
}

impl AuthorityChain {
    /// Create new empty authority chain
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            relationships: HashMap::new(),
            reverse_relationships: HashMap::new(),
        }
    }
    
    /// Add key to authority chain
    pub fn add_key(&mut self, key: AuthorityKey) -> AgeResult<()> {
        let fingerprint = key.fingerprint().clone();
        
        // Validate key is not already present
        if self.keys.contains_key(&fingerprint) {
            return Err(AgeError::InvalidOperation {
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
    
    /// Add authority relationship
    pub fn add_authority_relationship(
        &mut self,
        parent: &KeyFingerprint,
        child: &KeyFingerprint,
    ) -> AgeResult<()> {
        // Validate both keys exist
        let parent_key = self.get_key(parent)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!("Parent key not found: {}", parent),
            })?;
        let child_key = self.get_key(child)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!("Child key not found: {}", child),
            })?;
        
        // Validate authority relationship is valid
        if !parent_key.key_type().can_control(child_key.key_type()) {
            return Err(AgeError::InvalidOperation {
                operation: "add_authority".to_string(),
                reason: format!(
                    "Invalid authority relationship: {} cannot control {}",
                    parent_key.key_type(),
                    child_key.key_type()
                ),
            });
        }
        
        // Add to relationships
        self.relationships.entry(parent.clone())
            .or_insert_with(Vec::new)
            .push(child.clone());
        self.reverse_relationships.insert(child.clone(), parent.clone());
        
        // Update key's authority relationships
        if let Some(parent_key) = self.get_key_mut(parent) {
            parent_key.add_authority_relationship(child.clone());
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
    
    /// Find dependent keys that would be affected by key rotation
    pub fn find_dependent_keys(&self, target: &KeyFingerprint) -> AgeResult<Vec<AuthorityKey>> {
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
    pub fn validate_integrity(&self) -> AgeResult<()> {
        // Check for cycles
        for (parent_fp, children) in &self.relationships {
            for child_fp in children {
                if self.has_authority_path(child_fp, parent_fp) {
                    return Err(AgeError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!("Authority cycle detected: {} -> {}", parent_fp, child_fp),
                    });
                }
            }
        }
        
        // Validate all relationships follow hierarchy rules
        for (parent_fp, children) in &self.relationships {
            let parent_key = self.get_key(parent_fp)
                .ok_or_else(|| AgeError::InvalidOperation {
                    operation: "validate_integrity".to_string(),
                    reason: format!("Missing parent key: {}", parent_fp),
                })?;
            
            for child_fp in children {
                let child_key = self.get_key(child_fp)
                    .ok_or_else(|| AgeError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!("Missing child key: {}", child_fp),
                    })?;
                
                if !parent_key.key_type().can_control(child_key.key_type()) {
                    return Err(AgeError::InvalidOperation {
                        operation: "validate_integrity".to_string(),
                        reason: format!(
                            "Invalid hierarchy: {} cannot control {}",
                            parent_key.key_type(),
                            child_key.key_type()
                        ),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Check if there's an authority path from start to end
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
    
    #[test]
    fn test_key_type_hierarchy() {
        assert!(KeyType::Skull.can_control(KeyType::Master));
        assert!(KeyType::Master.can_control(KeyType::Repo));
        assert!(KeyType::Repo.can_control(KeyType::Ignition));
        assert!(KeyType::Ignition.can_control(KeyType::Distro));
        
        assert!(!KeyType::Distro.can_control(KeyType::Ignition));
        assert!(!KeyType::Master.can_control(KeyType::Ignition)); // Must go through Repo
    }
    
    #[test]
    fn test_key_type_ignition_detection() {
        assert!(KeyType::Skull.is_ignition_key());
        assert!(!KeyType::Master.is_ignition_key());
        assert!(!KeyType::Repo.is_ignition_key());
        assert!(KeyType::Ignition.is_ignition_key());
        assert!(KeyType::Distro.is_ignition_key());
    }
    
    #[test]
    fn test_authority_chain_basic() {
        let mut chain = AuthorityChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }
}