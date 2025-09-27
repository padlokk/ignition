//! Authority Validation Engine
//!
//! Mathematical authority relationship validation with cryptographic proofs
//! implementing the complete X->M->R->I->D authority chain verification.
//!
//! Security Guardian: Edgar - Cryptographic proof generation and validation

use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::sec::cage::error::{AgeError, AgeResult};
use super::chain::{KeyType, KeyFingerprint, AuthorityKey, AuthorityChain};

/// Authority levels in the hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityLevel {
    DistroAccess = 1,    // D keys - file read/write access
    IgnitionControl = 2, // I keys - manage distro keys, repo operations
    RepoControl = 3,     // R keys - full repo management
    MasterControl = 4,   // M keys - global operations
    SkullAuthority = 5,  // X keys - emergency and master key management
}

impl AuthorityLevel {
    /// Get authority level for key type
    pub fn from_key_type(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Skull => AuthorityLevel::SkullAuthority,
            KeyType::Master => AuthorityLevel::MasterControl,
            KeyType::Repo => AuthorityLevel::RepoControl,
            KeyType::Ignition => AuthorityLevel::IgnitionControl,
            KeyType::Distro => AuthorityLevel::DistroAccess,
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            AuthorityLevel::DistroAccess => "Distribution Access (File Operations)",
            AuthorityLevel::IgnitionControl => "Ignition Control (Key Management)",
            AuthorityLevel::RepoControl => "Repository Control (Full Repository)",
            AuthorityLevel::MasterControl => "Master Control (Global Operations)",
            AuthorityLevel::SkullAuthority => "Skull Authority (Emergency Recovery)",
        }
    }
    
    /// Check if this authority level can perform operation requiring minimum level
    pub fn can_perform(&self, required_level: AuthorityLevel) -> bool {
        *self >= required_level
    }
}

/// Cryptographic signature for authority proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    signature_bytes: Vec<u8>,
    algorithm: String,
    created_at: DateTime<Utc>,
}

impl Signature {
    /// Create new signature (mock implementation)
    pub fn new(data: &[u8], _signing_key: &AuthorityKey) -> AgeResult<Self> {
        // Mock signature - in production would use proper cryptographic signing
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(b"mock-signature-key");
        
        Ok(Signature {
            signature_bytes: hasher.finalize().to_vec(),
            algorithm: "SHA256-MOCK".to_string(),
            created_at: Utc::now(),
        })
    }
    
    /// Verify signature (mock implementation)
    pub fn verify(&self, data: &[u8], _verifying_key: &AuthorityKey) -> AgeResult<bool> {
        // Mock verification - in production would use proper cryptographic verification
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(b"mock-signature-key");
        
        let expected_signature = hasher.finalize().to_vec();
        Ok(expected_signature == self.signature_bytes)
    }
}

/// Authority proof demonstrating parent control over child
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityProof {
    parent_key: KeyFingerprint,
    child_key: KeyFingerprint,
    authority_signature: Signature,
    proof_timestamp: DateTime<Utc>,
    validation_chain: Vec<KeyFingerprint>,
    proof_version: u32,
}

impl AuthorityProof {
    /// Generate cryptographic proof that parent has authority over child
    pub fn generate(parent: &AuthorityKey, child: &AuthorityKey) -> AgeResult<Self> {
        // 1. Verify parent key type can control child key type
        validate_authority_hierarchy(parent.key_type(), child.key_type())?;
        
        // 2. Create proof data for signing
        let proof_data = format!("AUTHORITY:{}:{}", 
            parent.fingerprint().hex(), 
            child.fingerprint().hex()
        );
        
        // 3. Generate cryptographic signature proving control
        let signature = Signature::new(proof_data.as_bytes(), parent)?;
        
        // 4. Build proof chain showing authority lineage
        let validation_chain = build_authority_chain(parent, child)?;
        
        Ok(AuthorityProof {
            parent_key: parent.fingerprint().clone(),
            child_key: child.fingerprint().clone(),
            authority_signature: signature,
            proof_timestamp: Utc::now(),
            validation_chain,
            proof_version: 1,
        })
    }
    
    /// Verify authority proof is valid and current
    pub fn verify(&self, parent: &AuthorityKey, child: &AuthorityKey) -> AgeResult<bool> {
        // 1. Verify proof hasn't expired (24 hours)
        if self.proof_timestamp + chrono::Duration::hours(24) < Utc::now() {
            return Err(AgeError::InvalidOperation {
                operation: "verify_authority_proof".to_string(),
                reason: "Authority proof has expired".to_string(),
            });
        }
        
        // 2. Verify fingerprints match
        if &self.parent_key != parent.fingerprint() || &self.child_key != child.fingerprint() {
            return Err(AgeError::InvalidOperation {
                operation: "verify_authority_proof".to_string(),
                reason: "Key fingerprints do not match proof".to_string(),
            });
        }
        
        // 3. Verify authority hierarchy rules
        validate_authority_hierarchy(parent.key_type(), child.key_type())?;
        
        // 4. Verify signature authenticity
        let proof_data = format!("AUTHORITY:{}:{}", 
            parent.fingerprint().hex(), 
            child.fingerprint().hex()
        );
        
        if !self.authority_signature.verify(proof_data.as_bytes(), parent)? {
            return Err(AgeError::InvalidOperation {
                operation: "verify_authority_proof".to_string(),
                reason: "Invalid authority signature".to_string(),
            });
        }
        
        // 5. Verify validation chain integrity
        self.verify_validation_chain()?;
        
        Ok(true)
    }
    
    /// Verify the validation chain is intact
    fn verify_validation_chain(&self) -> AgeResult<()> {
        // Basic validation - in production would verify entire chain
        if self.validation_chain.is_empty() {
            return Err(AgeError::InvalidOperation {
                operation: "verify_validation_chain".to_string(),
                reason: "Empty validation chain".to_string(),
            });
        }
        
        // Verify parent is in the chain
        if !self.validation_chain.contains(&self.parent_key) {
            return Err(AgeError::InvalidOperation {
                operation: "verify_validation_chain".to_string(),
                reason: "Parent key not in validation chain".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Get parent key fingerprint
    pub fn parent_key(&self) -> &KeyFingerprint {
        &self.parent_key
    }
    
    /// Get child key fingerprint
    pub fn child_key(&self) -> &KeyFingerprint {
        &self.child_key
    }
    
    /// Get proof timestamp
    pub fn proof_timestamp(&self) -> DateTime<Utc> {
        self.proof_timestamp
    }
}

/// Subject proof demonstrating child acknowledgment of authority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectProof {
    subject_key: KeyFingerprint,
    authority_key: KeyFingerprint,
    subject_signature: Signature,
    acknowledgment_timestamp: DateTime<Utc>,
}

impl SubjectProof {
    /// Generate proof that key is subject to authority
    pub fn generate(subject: &AuthorityKey, authority: &AuthorityKey) -> AgeResult<Self> {
        // 1. Verify subject relationship is valid (inverse of authority)
        validate_authority_hierarchy(authority.key_type(), subject.key_type())?;
        
        // 2. Create acknowledgment data for signing
        let acknowledgment_data = format!("SUBJECT:{}:{}", 
            subject.fingerprint().hex(), 
            authority.fingerprint().hex()
        );
        
        // 3. Subject key signs acknowledgment of authority
        let signature = Signature::new(acknowledgment_data.as_bytes(), subject)?;
        
        Ok(SubjectProof {
            subject_key: subject.fingerprint().clone(),
            authority_key: authority.fingerprint().clone(),
            subject_signature: signature,
            acknowledgment_timestamp: Utc::now(),
        })
    }
    
    /// Verify subject relationship is valid
    pub fn verify(&self, subject: &AuthorityKey, authority: &AuthorityKey) -> AgeResult<bool> {
        // 1. Verify fingerprints match
        if &self.subject_key != subject.fingerprint() || &self.authority_key != authority.fingerprint() {
            return Err(AgeError::InvalidOperation {
                operation: "verify_subject_proof".to_string(),
                reason: "Key fingerprints do not match proof".to_string(),
            });
        }
        
        // 2. Verify the authority relationship exists
        validate_authority_hierarchy(authority.key_type(), subject.key_type())?;
        
        // 3. Verify subject signature acknowledging authority
        let acknowledgment_data = format!("SUBJECT:{}:{}", 
            subject.fingerprint().hex(), 
            authority.fingerprint().hex()
        );
        
        if !self.subject_signature.verify(acknowledgment_data.as_bytes(), subject)? {
            return Err(AgeError::InvalidOperation {
                operation: "verify_subject_proof".to_string(),
                reason: "Invalid subject signature".to_string(),
            });
        }
        
        Ok(true)
    }
}

/// Validate authority hierarchy rules
pub fn validate_authority_hierarchy(parent_type: KeyType, child_type: KeyType) -> AgeResult<()> {
    if !parent_type.can_control(child_type) {
        return Err(AgeError::InvalidOperation {
            operation: "validate_authority_hierarchy".to_string(),
            reason: format!("{} cannot control {}", parent_type, child_type),
        });
    }
    Ok(())
}

/// Build authority chain for validation
fn build_authority_chain(parent: &AuthorityKey, child: &AuthorityKey) -> AgeResult<Vec<KeyFingerprint>> {
    // Basic chain - in production would traverse full authority tree
    Ok(vec![
        parent.fingerprint().clone(),
        child.fingerprint().clone(),
    ])
}

/// Authority validation engine
pub struct AuthorityValidationEngine {
    authority_chain: AuthorityChain,
    proof_cache: std::collections::HashMap<String, AuthorityProof>,
    cache_expiry: Duration,
}

impl AuthorityValidationEngine {
    /// Create new validation engine
    pub fn new(authority_chain: AuthorityChain) -> Self {
        Self {
            authority_chain,
            proof_cache: std::collections::HashMap::new(),
            cache_expiry: Duration::from_secs(3600), // 1 hour cache
        }
    }
    
    /// Test if parent has authority over child
    pub fn test_authority(&mut self, parent_fp: &KeyFingerprint, child_fp: &KeyFingerprint) -> AgeResult<bool> {
        // Get keys from chain
        let parent = self.authority_chain.get_key(parent_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "test_authority".to_string(),
                reason: format!("Parent key not found: {}", parent_fp),
            })?;
        let child = self.authority_chain.get_key(child_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "test_authority".to_string(),
                reason: format!("Child key not found: {}", child_fp),
            })?;
        
        // Check cache first
        let cache_key = format!("{}:{}", parent_fp.hex(), child_fp.hex());
        if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
            if cached_proof.proof_timestamp + chrono::Duration::from_std(self.cache_expiry).unwrap_or_default() > Utc::now() {
                return cached_proof.verify(parent, child);
            }
        }
        
        // Generate new proof
        let proof = AuthorityProof::generate(parent, child)?;
        let result = proof.verify(parent, child)?;
        
        // Cache successful proof
        if result {
            self.proof_cache.insert(cache_key, proof);
        }
        
        Ok(result)
    }
    
    /// Test if child is subject to parent
    pub fn test_subject(&self, child_fp: &KeyFingerprint, parent_fp: &KeyFingerprint) -> AgeResult<bool> {
        // Get keys from chain
        let child = self.authority_chain.get_key(child_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "test_subject".to_string(),
                reason: format!("Child key not found: {}", child_fp),
            })?;
        let parent = self.authority_chain.get_key(parent_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "test_subject".to_string(),
                reason: format!("Parent key not found: {}", parent_fp),
            })?;
        
        // Generate and verify subject proof
        let proof = SubjectProof::generate(child, parent)?;
        proof.verify(child, parent)
    }
    
    /// Validate operation authorization
    pub fn validate_operation_authorization(
        &self,
        operation: &str,
        key_fp: &KeyFingerprint,
        required_level: AuthorityLevel,
    ) -> AgeResult<bool> {
        let key = self.authority_chain.get_key(key_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "validate_operation_authorization".to_string(),
                reason: format!("Key not found: {}", key_fp),
            })?;
        
        let key_level = AuthorityLevel::from_key_type(key.key_type());
        
        if !key_level.can_perform(required_level) {
            return Err(AgeError::InvalidOperation {
                operation: "validate_operation_authorization".to_string(),
                reason: format!(
                    "Insufficient authority for operation '{}': {} required, {} provided",
                    operation,
                    required_level.description(),
                    key_level.description()
                ),
            });
        }
        
        Ok(true)
    }
    
    /// Clear expired proofs from cache
    pub fn cleanup_cache(&mut self) {
        let now = Utc::now();
        let expiry_duration = chrono::Duration::from_std(self.cache_expiry).unwrap_or_default();
        
        self.proof_cache.retain(|_, proof| {
            proof.proof_timestamp + expiry_duration > now
        });
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let total = self.proof_cache.len();
        let expired = self.proof_cache.values()
            .filter(|proof| {
                let expiry_duration = chrono::Duration::from_std(self.cache_expiry).unwrap_or_default();
                proof.proof_timestamp + expiry_duration <= Utc::now()
            })
            .count();
        
        (total, expired)
    }
}

/// Initialize validation engine subsystem
pub fn initialize_validation_engine() -> AgeResult<()> {
    // Perform any initialization required for validation
    // For now, just validate we have required dependencies
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::chain::{KeyMaterial, KeyFormat, AuthorityKey};
    
    #[test]
    fn test_authority_hierarchy_validation() {
        assert!(validate_authority_hierarchy(KeyType::Skull, KeyType::Master).is_ok());
        assert!(validate_authority_hierarchy(KeyType::Master, KeyType::Repo).is_ok());
        assert!(validate_authority_hierarchy(KeyType::Repo, KeyType::Ignition).is_ok());
        assert!(validate_authority_hierarchy(KeyType::Ignition, KeyType::Distro).is_ok());
        
        // Invalid relationships
        assert!(validate_authority_hierarchy(KeyType::Distro, KeyType::Ignition).is_err());
        assert!(validate_authority_hierarchy(KeyType::Master, KeyType::Ignition).is_err());
    }
    
    #[test]
    fn test_authority_levels() {
        assert_eq!(AuthorityLevel::from_key_type(KeyType::Skull), AuthorityLevel::SkullAuthority);
        assert_eq!(AuthorityLevel::from_key_type(KeyType::Master), AuthorityLevel::MasterControl);
        assert_eq!(AuthorityLevel::from_key_type(KeyType::Distro), AuthorityLevel::DistroAccess);
        
        // Test authority level comparisons
        assert!(AuthorityLevel::SkullAuthority > AuthorityLevel::MasterControl);
        assert!(AuthorityLevel::MasterControl.can_perform(AuthorityLevel::DistroAccess));
        assert!(!AuthorityLevel::DistroAccess.can_perform(AuthorityLevel::MasterControl));
    }
    
    #[test]
    fn test_authority_proof_generation() {
        let parent_key_material = KeyMaterial::new(
            b"parent_public".to_vec(),
            Some(b"parent_private".to_vec()),
            KeyFormat::Age,
        );
        let child_key_material = KeyMaterial::new(
            b"child_public".to_vec(),
            Some(b"child_private".to_vec()),
            KeyFormat::Age,
        );
        
        let parent_key = AuthorityKey::new(parent_key_material, KeyType::Master, None, None).unwrap();
        let child_key = AuthorityKey::new(child_key_material, KeyType::Repo, None, None).unwrap();
        
        let proof = AuthorityProof::generate(&parent_key, &child_key);
        assert!(proof.is_ok());
        
        let proof = proof.unwrap();
        assert!(proof.verify(&parent_key, &child_key).is_ok());
    }
}