//! Ignition Key Management
//!
//! Passphrase-wrapped key operations implementing secure key storage and access
//! control for X, I, and D key types in the authority chain.
//!
//! Security Guardian: Edgar - Secure passphrase wrapping and validation

use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::sec::cage::error::{AgeError, AgeResult};
use super::chain::{KeyType, KeyMaterial, KeyFingerprint, AuthorityKey};

/// Passphrase hash for secure verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseHash {
    hash: String,
    salt: String,
    algorithm: String,
    iterations: u32,
}

impl PassphraseHash {
    /// Create new passphrase hash with salt
    pub fn new(passphrase: &str) -> AgeResult<Self> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Generate salt
        let mut hasher = DefaultHasher::new();
        Utc::now().timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        let salt = format!("{:x}", hasher.finish());
        
        // Hash passphrase with salt
        let salted = format!("{}{}", passphrase, salt);
        let mut sha_hasher = Sha256::new();
        
        // Multiple iterations for security
        let iterations = 100_000;
        let mut current = salted.as_bytes().to_vec();
        for _ in 0..iterations {
            sha_hasher.update(&current);
            current = sha_hasher.finalize_reset().to_vec();
        }
        
        Ok(PassphraseHash {
            hash: format!("{:x}", Sha256::digest(&current)),
            salt,
            algorithm: "SHA256-PBKDF2".to_string(),
            iterations,
        })
    }
    
    /// Verify passphrase against hash
    pub fn verify(&self, passphrase: &str) -> AgeResult<bool> {
        let salted = format!("{}{}", passphrase, self.salt);
        let mut sha_hasher = Sha256::new();
        
        let mut current = salted.as_bytes().to_vec();
        for _ in 0..self.iterations {
            sha_hasher.update(&current);
            current = sha_hasher.finalize_reset().to_vec();
        }
        
        let computed_hash = format!("{:x}", Sha256::digest(&current));
        Ok(computed_hash == self.hash)
    }
}

/// Encrypted key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyMaterial {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    algorithm: String,
}

impl EncryptedKeyMaterial {
    /// Encrypt key material with derived key
    pub fn encrypt(key_material: &KeyMaterial, encryption_key: &[u8]) -> AgeResult<Self> {
        // Simple XOR encryption for demo (should use proper AES-GCM in production)
        let plaintext = serde_json::to_vec(key_material)
            .map_err(|e| AgeError::InvalidOperation {
                operation: "serialize_key".to_string(),
                reason: e.to_string(),
            })?;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ encryption_key[i % encryption_key.len()]);
        }
        
        // Generate nonce (mock for demo)
        let nonce = vec![0u8; 12]; // Should be random in production
        
        Ok(EncryptedKeyMaterial {
            ciphertext,
            nonce,
            algorithm: "XOR-DEMO".to_string(), // Would be "AES-256-GCM" in production
        })
    }
    
    /// Decrypt key material with derived key
    pub fn decrypt(&self, encryption_key: &[u8]) -> AgeResult<KeyMaterial> {
        // Simple XOR decryption for demo
        let mut plaintext = Vec::with_capacity(self.ciphertext.len());
        for (i, &byte) in self.ciphertext.iter().enumerate() {
            plaintext.push(byte ^ encryption_key[i % encryption_key.len()]);
        }
        
        let key_material: KeyMaterial = serde_json::from_slice(&plaintext)
            .map_err(|e| AgeError::InvalidOperation {
                operation: "deserialize_key".to_string(),
                reason: e.to_string(),
            })?;
        
        Ok(key_material)
    }
}

/// Expiration policy for ignition keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationPolicy {
    expiration_duration: Duration,
    auto_rotation: bool,
    warning_threshold: Duration,
}

impl ExpirationPolicy {
    /// Create new expiration policy
    pub fn new(duration: Duration, auto_rotation: bool) -> Self {
        Self {
            expiration_duration: duration,
            auto_rotation,
            warning_threshold: Duration::from_secs(duration.as_secs() / 10), // 10% warning
        }
    }
    
    /// Check if key is expired based on creation time
    pub fn is_expired(&self, creation_time: DateTime<Utc>) -> bool {
        let expiration_time = creation_time + chrono::Duration::from_std(self.expiration_duration).unwrap_or_default();
        Utc::now() > expiration_time
    }
    
    /// Check if key is approaching expiration
    pub fn is_warning(&self, creation_time: DateTime<Utc>) -> bool {
        let warning_time = creation_time 
            + chrono::Duration::from_std(self.expiration_duration).unwrap_or_default()
            - chrono::Duration::from_std(self.warning_threshold).unwrap_or_default();
        Utc::now() > warning_time
    }
    
    /// Default expiration policy for key type
    pub fn default_for_type(key_type: KeyType) -> Option<Self> {
        match key_type {
            KeyType::Skull => None, // Skull keys don't expire
            KeyType::Master => None, // Master keys don't auto-expire
            KeyType::Repo => None, // Repo keys managed manually
            KeyType::Ignition => Some(Self::new(Duration::from_secs(86400 * 30), true)), // 30 days
            KeyType::Distro => Some(Self::new(Duration::from_secs(86400 * 7), true)), // 7 days
        }
    }
}

/// Ignition key with passphrase protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnitionKey {
    wrapped_key: EncryptedKeyMaterial,
    key_type: KeyType,
    passphrase_hash: PassphraseHash,
    authority_chain: Vec<KeyFingerprint>,
    creation_timestamp: DateTime<Utc>,
    expiration_policy: Option<ExpirationPolicy>,
    metadata: IgnitionKeyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnitionKeyMetadata {
    pub name: String,
    pub description: String,
    pub creator: String,
    pub last_unlock: Option<DateTime<Utc>>,
    pub unlock_count: u64,
    pub failed_unlock_attempts: u64,
}

impl Default for IgnitionKeyMetadata {
    fn default() -> Self {
        Self {
            name: "unnamed".to_string(),
            description: "Ignition key".to_string(),
            creator: "unknown".to_string(),
            last_unlock: None,
            unlock_count: 0,
            failed_unlock_attempts: 0,
        }
    }
}

impl IgnitionKey {
    /// Create new ignition key with passphrase protection
    pub fn create(
        key_material: &KeyMaterial,
        key_type: KeyType,
        passphrase: &str,
        authority_parent: Option<&AuthorityKey>,
        name: Option<String>,
    ) -> AgeResult<Self> {
        // Validate key type can be ignition key
        if !key_type.is_ignition_key() {
            return Err(AgeError::InvalidOperation {
                operation: "create_ignition_key".to_string(),
                reason: format!("Key type {} cannot be an ignition key", key_type),
            });
        }
        
        // Validate passphrase strength
        validate_passphrase_strength(passphrase)?;
        
        // Derive encryption key from passphrase
        let encryption_key = derive_encryption_key(passphrase)?;
        
        // Encrypt key material
        let wrapped_key = EncryptedKeyMaterial::encrypt(key_material, &encryption_key)?;
        
        // Build authority chain if parent provided
        let authority_chain = if let Some(parent) = authority_parent {
            build_authority_chain_to_parent(parent)?
        } else {
            Vec::new()
        };
        
        // Create passphrase hash
        let passphrase_hash = PassphraseHash::new(passphrase)?;
        
        let mut metadata = IgnitionKeyMetadata::default();
        if let Some(n) = name {
            metadata.name = n;
        }
        
        Ok(IgnitionKey {
            wrapped_key,
            key_type,
            passphrase_hash,
            authority_chain,
            creation_timestamp: Utc::now(),
            expiration_policy: ExpirationPolicy::default_for_type(key_type),
            metadata,
        })
    }
    
    /// Unlock ignition key with passphrase
    pub fn unlock(&mut self, passphrase: &str) -> AgeResult<KeyMaterial> {
        // Check if key has expired
        if let Some(policy) = &self.expiration_policy {
            if policy.is_expired(self.creation_timestamp) {
                return Err(AgeError::InvalidOperation {
                    operation: "unlock_ignition_key".to_string(),
                    reason: "Ignition key has expired".to_string(),
                });
            }
        }
        
        // Verify passphrase
        if !self.passphrase_hash.verify(passphrase)? {
            self.metadata.failed_unlock_attempts += 1;
            return Err(AgeError::InvalidOperation {
                operation: "unlock_ignition_key".to_string(),
                reason: "Invalid passphrase".to_string(),
            });
        }
        
        // Derive decryption key and unlock
        let decryption_key = derive_encryption_key(passphrase)?;
        let key_material = self.wrapped_key.decrypt(&decryption_key)?;
        
        // Update metadata
        self.metadata.last_unlock = Some(Utc::now());
        self.metadata.unlock_count += 1;
        
        Ok(key_material)
    }
    
    /// Change passphrase for ignition key
    pub fn change_passphrase(&mut self, old_passphrase: &str, new_passphrase: &str) -> AgeResult<()> {
        // Verify old passphrase and unlock key
        let key_material = self.unlock(old_passphrase)?;
        
        // Validate new passphrase strength
        validate_passphrase_strength(new_passphrase)?;
        
        // Re-encrypt with new passphrase
        let new_encryption_key = derive_encryption_key(new_passphrase)?;
        self.wrapped_key = EncryptedKeyMaterial::encrypt(&key_material, &new_encryption_key)?;
        self.passphrase_hash = PassphraseHash::new(new_passphrase)?;
        
        Ok(())
    }
    
    /// Check if ignition key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(policy) = &self.expiration_policy {
            policy.is_expired(self.creation_timestamp)
        } else {
            false
        }
    }
    
    /// Check if ignition key is approaching expiration
    pub fn is_warning(&self) -> bool {
        if let Some(policy) = &self.expiration_policy {
            policy.is_warning(self.creation_timestamp)
        } else {
            false
        }
    }
    
    /// Get key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    
    /// Get creation timestamp
    pub fn creation_timestamp(&self) -> DateTime<Utc> {
        self.creation_timestamp
    }
    
    /// Get metadata
    pub fn metadata(&self) -> &IgnitionKeyMetadata {
        &self.metadata
    }
    
    /// Get authority chain
    pub fn authority_chain(&self) -> &[KeyFingerprint] {
        &self.authority_chain
    }
    
    /// Update metadata
    pub fn update_metadata(&mut self, metadata: IgnitionKeyMetadata) {
        self.metadata = metadata;
    }
    
    /// Get key fingerprint derived from wrapped key material
    pub fn fingerprint(&self) -> AgeResult<KeyFingerprint> {
        // Generate fingerprint from the encrypted key material
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.wrapped_key.ciphertext);
        hasher.update(&self.key_type.to_string().as_bytes());
        hasher.update(&self.creation_timestamp.timestamp().to_be_bytes());
        
        let hash = hasher.finalize();
        
        // Use the existing from_key_material method
        KeyFingerprint::from_key_material(&hash[..16])
    }
}

/// Validate passphrase strength according to security requirements
pub fn validate_passphrase_strength(passphrase: &str) -> AgeResult<()> {
    // Minimum length requirement
    if passphrase.len() < 12 {
        return Err(AgeError::InvalidOperation {
            operation: "validate_passphrase".to_string(),
            reason: "Passphrase must be at least 12 characters long".to_string(),
        });
    }
    
    // Maximum length to prevent DoS
    if passphrase.len() > 256 {
        return Err(AgeError::InvalidOperation {
            operation: "validate_passphrase".to_string(),
            reason: "Passphrase must be less than 256 characters".to_string(),
        });
    }
    
    // Character diversity requirements
    let has_upper = passphrase.chars().any(|c| c.is_uppercase());
    let has_lower = passphrase.chars().any(|c| c.is_lowercase());
    let has_digit = passphrase.chars().any(|c| c.is_numeric());
    let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());
    
    let diversity_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    if diversity_count < 3 {
        return Err(AgeError::InvalidOperation {
            operation: "validate_passphrase".to_string(),
            reason: "Passphrase must contain at least 3 of: uppercase, lowercase, digits, special characters".to_string(),
        });
    }
    
    // Common password detection (basic check)
    if is_common_password(passphrase) {
        return Err(AgeError::InvalidOperation {
            operation: "validate_passphrase".to_string(),
            reason: "Common password detected. Please use a unique passphrase".to_string(),
        });
    }
    
    // Injection pattern detection (from security.rs patterns)
    let injection_patterns = ["$(", "`", ";", "&", "|", "\n", "\r", "\0"];
    for pattern in &injection_patterns {
        if passphrase.contains(pattern) {
            return Err(AgeError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: format!("Passphrase contains dangerous pattern: {}", pattern),
            });
        }
    }
    
    Ok(())
}

/// Check if passphrase is a common/weak password
fn is_common_password(passphrase: &str) -> bool {
    // Basic check for common passwords
    let common_passwords = [
        "password", "123456", "password123", "admin", "qwerty",
        "letmein", "welcome", "monkey", "1234567890", "abc123",
    ];
    
    let lower_passphrase = passphrase.to_lowercase();
    common_passwords.iter().any(|&p| lower_passphrase.contains(p))
}

/// Derive encryption key from passphrase using key derivation
fn derive_encryption_key(passphrase: &str) -> AgeResult<Vec<u8>> {
    // Simple key derivation (should use proper PBKDF2/Argon2 in production)
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(b"padlock-ignition-key-salt"); // Fixed salt for demo
    
    Ok(hasher.finalize().to_vec())
}

/// Build authority chain to parent key
fn build_authority_chain_to_parent(parent: &AuthorityKey) -> AgeResult<Vec<KeyFingerprint>> {
    // For now, just include the parent fingerprint
    // In a full implementation, this would traverse the entire chain
    Ok(vec![parent.fingerprint().clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::chain::{KeyMaterial, KeyFormat};
    
    #[test]
    fn test_passphrase_validation() {
        // Valid passphrase
        assert!(validate_passphrase_strength("MySecure123!Pass").is_ok());
        
        // Too short
        assert!(validate_passphrase_strength("short").is_err());
        
        // No diversity
        assert!(validate_passphrase_strength("alllowercase").is_err());
        
        // Common password
        assert!(validate_passphrase_strength("password123").is_err());
        
        // Injection pattern
        assert!(validate_passphrase_strength("test$(rm -rf /)").is_err());
    }
    
    #[test]
    fn test_passphrase_hash() {
        let passphrase = "TestPassphrase123!";
        let hash = PassphraseHash::new(passphrase).unwrap();
        
        // Correct passphrase should verify
        assert!(hash.verify(passphrase).unwrap());
        
        // Wrong passphrase should not verify
        assert!(!hash.verify("WrongPassphrase").unwrap());
    }
    
    #[test]
    fn test_ignition_key_creation() {
        let key_material = KeyMaterial::new(
            b"test_public_key".to_vec(),
            Some(b"test_private_key".to_vec()),
            KeyFormat::Age,
        );
        
        let ignition_key = IgnitionKey::create(
            &key_material,
            KeyType::Ignition,
            "SecureTestPass123!",
            None,
            Some("test-key".to_string()),
        );
        
        assert!(ignition_key.is_ok());
        let key = ignition_key.unwrap();
        assert_eq!(key.key_type(), KeyType::Ignition);
        assert_eq!(key.metadata().name, "test-key");
    }
}