//! Key Generation Operations - Authority-aware Age key generation
//!
//! Implements Story 2.1: Key Generation Operations with proper Authority Chain integration.
//! Generates real Age keys with authority relationships and integrates with proven TTY automation.
//!
//! Security Guardian: Edgar - Real Age key generation with authority validation

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::fs;
use tempfile::NamedTempFile;
use chrono::{DateTime, Utc};

use crate::sec::cage::{
    error::{AgeError, AgeResult},
    security::AuditLogger,
};
use super::super::{
    KeyType, AuthorityChain, AuthorityKey, KeyFingerprint,
    validation::AuthorityValidationEngine,
    chain::{KeyMaterial, KeyFormat, KeyMetadata},
};

/// Age key generation with authority integration
pub struct AuthorityAgeKeyGenerator {
    authority_chain: AuthorityChain,
    validation_engine: AuthorityValidationEngine,
    audit_logger: AuditLogger,
}

/// Generated Age key with authority metadata
#[derive(Debug, Clone)]
pub struct GeneratedAgeKey {
    pub authority_key: AuthorityKey,
    pub age_public_key: String,
    pub age_secret_key: String,
    pub key_file_path: Option<PathBuf>,
    pub generation_timestamp: DateTime<Utc>,
}

impl AuthorityAgeKeyGenerator {
    /// Create new Age key generator with authority validation
    pub fn new(authority_chain: AuthorityChain, audit_log_path: Option<PathBuf>) -> AgeResult<Self> {
        let validation_engine = AuthorityValidationEngine::new(authority_chain.clone());
        let audit_logger = AuditLogger::new(audit_log_path)?;
        
        Ok(Self {
            authority_chain,
            validation_engine,
            audit_logger,
        })
    }
    
    /// Generate Age key with authority validation
    pub fn generate_authority_age_key(
        &mut self,
        key_type: KeyType,
        parent_authority: Option<&KeyFingerprint>,
        key_name: String,
        output_path: Option<&Path>,
    ) -> AgeResult<GeneratedAgeKey> {
        self.audit_logger.log_operation_start("generate_authority_age_key", 
            Path::new(&format!("key_type:{}", key_type)), 
            Path::new(&key_name))?;
        
        // 1. Validate authority if parent specified
        if let Some(parent_fp) = parent_authority {
            self.validate_parent_authority(key_type, parent_fp)?;
        }
        
        // 2. Generate Age key using age-keygen
        let (age_public, age_secret) = self.generate_age_keypair()?;
        
        // 3. Create key material from Age key
        let key_material = KeyMaterial::new(
            age_public.as_bytes().to_vec(),
            Some(age_secret.as_bytes().to_vec()),
            KeyFormat::Age,
        );
        
        // 4. Create authority key with metadata
        let metadata = KeyMetadata {
            creation_time: Utc::now(),
            creator: "authority_age_generator".to_string(),
            description: format!("{} authority key: {}", key_type, key_name),
            expiration: None,
            last_used: None,
            usage_count: 0,
        };
        
        let authority_key = AuthorityKey::new(
            key_material,
            key_type,
            output_path.map(|p| p.to_path_buf()),
            Some(metadata),
        )?;
        
        // 5. Write key file if path specified
        let key_file_path = if let Some(path) = output_path {
            self.write_age_key_file(path, &age_secret)?;
            Some(path.to_path_buf())
        } else {
            None
        };
        
        // 6. Create generation result
        let generated_key = GeneratedAgeKey {
            authority_key,
            age_public_key: age_public,
            age_secret_key: age_secret,
            key_file_path,
            generation_timestamp: Utc::now(),
        };
        
        self.audit_logger.log_operation_success("generate_authority_age_key",
            Path::new(&format!("key_type:{}", key_type)),
            Path::new(&key_name))?;
        
        Ok(generated_key)
    }
    
    /// Generate Age keypair using age-keygen command
    fn generate_age_keypair(&self) -> AgeResult<(String, String)> {
        // Use age-keygen to generate real Age key
        let output = Command::new("age-keygen")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| AgeError::ProcessExecutionFailed {
                command: "age-keygen".to_string(),
                exit_code: None,
                stderr: e.to_string(),
            })?;
        
        if !output.status.success() {
            return Err(AgeError::ProcessExecutionFailed {
                command: "age-keygen".to_string(),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        
        let key_output = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = key_output.trim().lines().collect();
        
        if lines.len() < 3 {
            return Err(AgeError::InvalidOperation {
                operation: "parse_age_key".to_string(),
                reason: "Unexpected age-keygen output format".to_string(),
            });
        }
        
        // Parse Age key output
        // Line 1: # created: timestamp
        // Line 2: # public key: age1...
        // Line 3: AGE-SECRET-KEY-...
        
        let public_key_line = lines[1];
        let secret_key_line = lines[2];
        
        if !public_key_line.starts_with("# public key: age1") {
            return Err(AgeError::InvalidOperation {
                operation: "parse_age_public_key".to_string(),
                reason: "Invalid public key format".to_string(),
            });
        }
        
        if !secret_key_line.starts_with("AGE-SECRET-KEY-") {
            return Err(AgeError::InvalidOperation {
                operation: "parse_age_secret_key".to_string(),
                reason: "Invalid secret key format".to_string(),
            });
        }
        
        let public_key = public_key_line.replace("# public key: ", "");
        let secret_key = secret_key_line.to_string();
        
        Ok((public_key, secret_key))
    }
    
    /// Write Age key to file
    fn write_age_key_file(&self, path: &Path, secret_key: &str) -> AgeResult<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AgeError::file_error("create_dir", parent.to_path_buf(), e))?;
        }
        
        // Write Age key in standard format
        let key_content = format!("# created: {}\n# public key: {}\n{}\n",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%z"),
            self.extract_public_key_from_secret(secret_key)?,
            secret_key
        );
        
        fs::write(path, key_content)
            .map_err(|e| AgeError::file_error("write", path.to_path_buf(), e))?;
        
        // Set secure permissions (user read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| AgeError::file_error("metadata", path.to_path_buf(), e))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .map_err(|e| AgeError::file_error("set_permissions", path.to_path_buf(), e))?;
        }
        
        Ok(())
    }
    
    /// Extract public key from Age secret key using age-keygen -y
    fn extract_public_key_from_secret(&self, secret_key: &str) -> AgeResult<String> {
        // Create temporary file for secret key
        let mut temp_file = NamedTempFile::new()
            .map_err(|e| AgeError::TemporaryResourceError {
                resource_type: "file".to_string(),
                operation: "create".to_string(),
                reason: e.to_string(),
            })?;
        
        // Write secret key to temp file
        use std::io::Write;
        temp_file.write_all(secret_key.as_bytes())
            .map_err(|e| AgeError::TemporaryResourceError {
                resource_type: "file".to_string(),
                operation: "write".to_string(),
                reason: e.to_string(),
            })?;
        
        // Use age-keygen -y to extract public key
        let output = Command::new("age-keygen")
            .arg("-y")
            .arg(temp_file.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| AgeError::ProcessExecutionFailed {
                command: "age-keygen -y".to_string(),
                exit_code: None,
                stderr: e.to_string(),
            })?;
        
        if !output.status.success() {
            return Err(AgeError::ProcessExecutionFailed {
                command: "age-keygen -y".to_string(),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        
        let public_key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        if !public_key.starts_with("age1") {
            return Err(AgeError::InvalidOperation {
                operation: "extract_public_key".to_string(),
                reason: "Invalid public key extracted".to_string(),
            });
        }
        
        Ok(public_key)
    }
    
    /// Validate parent authority for key generation
    fn validate_parent_authority(&mut self, key_type: KeyType, parent_fp: &KeyFingerprint) -> AgeResult<()> {
        let parent_key = self.authority_chain.get_key(parent_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "validate_parent_authority".to_string(),
                reason: format!("Parent key not found: {}", parent_fp),
            })?;
        
        // Check if parent can control this key type
        if !parent_key.key_type().can_control(key_type) {
            return Err(AgeError::InvalidOperation {
                operation: "validate_parent_authority".to_string(),
                reason: format!(
                    "Parent {} cannot control key type {}",
                    parent_key.key_type(),
                    key_type
                ),
            });
        }
        
        Ok(())
    }
    
    /// Add generated key to authority chain
    pub fn add_to_authority_chain(&mut self, generated_key: &GeneratedAgeKey, parent_authority: Option<&KeyFingerprint>) -> AgeResult<()> {
        // Add key to chain
        self.authority_chain.add_key(generated_key.authority_key.clone())?;
        
        // Add authority relationship if parent specified
        if let Some(parent_fp) = parent_authority {
            let child_fp = generated_key.authority_key.fingerprint();
            self.authority_chain.add_authority_relationship(parent_fp, child_fp)?;
        }
        
        Ok(())
    }
    
    /// Generate complete authority chain from Skull to Distro
    pub fn generate_complete_authority_chain(&mut self, base_name: &str, output_dir: &Path) -> AgeResult<Vec<GeneratedAgeKey>> {
        let mut generated_keys = Vec::new();
        
        // 1. Generate Skull key (root authority)
        let skull_key = self.generate_authority_age_key(
            KeyType::Skull,
            None,
            format!("{}-skull", base_name),
            Some(&output_dir.join(format!("{}-skull.key", base_name))),
        )?;
        self.add_to_authority_chain(&skull_key, None)?;
        let skull_fp = skull_key.authority_key.fingerprint().clone();
        generated_keys.push(skull_key);
        
        // 2. Generate Master key (controlled by Skull)
        let master_key = self.generate_authority_age_key(
            KeyType::Master,
            Some(&skull_fp),
            format!("{}-master", base_name),
            Some(&output_dir.join(format!("{}-master.key", base_name))),
        )?;
        self.add_to_authority_chain(&master_key, Some(&skull_fp))?;
        let master_fp = master_key.authority_key.fingerprint().clone();
        generated_keys.push(master_key);
        
        // 3. Generate Repo key (controlled by Master)
        let repo_key = self.generate_authority_age_key(
            KeyType::Repo,
            Some(&master_fp),
            format!("{}-repo", base_name),
            Some(&output_dir.join(format!("{}-repo.key", base_name))),
        )?;
        self.add_to_authority_chain(&repo_key, Some(&master_fp))?;
        let repo_fp = repo_key.authority_key.fingerprint().clone();
        generated_keys.push(repo_key);
        
        // 4. Generate Ignition key (controlled by Repo)
        let ignition_key = self.generate_authority_age_key(
            KeyType::Ignition,
            Some(&repo_fp),
            format!("{}-ignition", base_name),
            Some(&output_dir.join(format!("{}-ignition.key", base_name))),
        )?;
        self.add_to_authority_chain(&ignition_key, Some(&repo_fp))?;
        let ignition_fp = ignition_key.authority_key.fingerprint().clone();
        generated_keys.push(ignition_key);
        
        // 5. Generate Distro key (controlled by Ignition)
        let distro_key = self.generate_authority_age_key(
            KeyType::Distro,
            Some(&ignition_fp),
            format!("{}-distro", base_name),
            Some(&output_dir.join(format!("{}-distro.key", base_name))),
        )?;
        self.add_to_authority_chain(&distro_key, Some(&ignition_fp))?;
        generated_keys.push(distro_key);
        
        // Validate complete chain integrity
        self.authority_chain.validate_integrity()?;
        
        Ok(generated_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_age_key_generation() {
        let temp_dir = TempDir::new().unwrap();
        let authority_chain = AuthorityChain::new();
        
        let mut generator = AuthorityAgeKeyGenerator::new(authority_chain, None).unwrap();
        
        let result = generator.generate_authority_age_key(
            KeyType::Master,
            None,
            "test-master".to_string(),
            Some(&temp_dir.path().join("test.key")),
        );
        
        assert!(result.is_ok(), "Age key generation should succeed");
        let generated = result.unwrap();
        assert!(generated.age_public_key.starts_with("age1"));
        assert!(generated.age_secret_key.starts_with("AGE-SECRET-KEY-"));
    }
    
    #[test]
    fn test_complete_authority_chain_generation() {
        let temp_dir = TempDir::new().unwrap();
        let authority_chain = AuthorityChain::new();
        
        let mut generator = AuthorityAgeKeyGenerator::new(authority_chain, None).unwrap();
        
        let result = generator.generate_complete_authority_chain("test", temp_dir.path());
        assert!(result.is_ok(), "Complete chain generation should succeed");
        
        let generated_keys = result.unwrap();
        assert_eq!(generated_keys.len(), 5, "Should generate all 5 key types");
        
        // Verify key types are in correct order
        assert_eq!(generated_keys[0].authority_key.key_type(), KeyType::Skull);
        assert_eq!(generated_keys[1].authority_key.key_type(), KeyType::Master);
        assert_eq!(generated_keys[2].authority_key.key_type(), KeyType::Repo);
        assert_eq!(generated_keys[3].authority_key.key_type(), KeyType::Ignition);
        assert_eq!(generated_keys[4].authority_key.key_type(), KeyType::Distro);
    }
}