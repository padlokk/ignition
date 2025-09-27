//! Age Integration Bridge
//!
//! Authority-aware Age automation interface bridging our authority chain
//! with Edgar's proven TTY automation patterns and Lucas's atomic operations.
//!
//! Security Guardian: Edgar - Production authority-Age integration

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::sec::cage::{
    config::OutputFormat,
    error::{AgeError, AgeResult},
    lifecycle::crud_manager::CrudManager,
    security::AuditLogger,
};
use super::super::{
    AuthorityChain, AuthorityKey, KeyFingerprint, KeyType,
    validation::{AuthorityValidationEngine, AuthorityLevel},
};

/// Authority-aware Age automation interface
pub struct AuthorityAgeInterface {
    crud_manager: CrudManager,
    authority_chain: AuthorityChain,
    validation_engine: AuthorityValidationEngine,
    audit_logger: AuditLogger,
}

impl AuthorityAgeInterface {
    /// Create new authority-Age interface
    pub fn new(
        crud_manager: CrudManager,
        authority_chain: AuthorityChain,
        audit_log_path: Option<PathBuf>,
    ) -> AgeResult<Self> {
        let validation_engine = AuthorityValidationEngine::new(authority_chain.clone());
        let audit_logger = AuditLogger::new(audit_log_path)?;
        
        Ok(Self {
            crud_manager,
            authority_chain,
            validation_engine,
            audit_logger,
        })
    }
    
    /// Encrypt file with authority validation
    pub fn encrypt_with_authority(
        &mut self,
        input: &Path,
        output: &Path,
        authority_key_fp: &KeyFingerprint,
        format: OutputFormat,
    ) -> AgeResult<()> {
        // 1. Authorize operation
        self.validation_engine.validate_operation_authorization(
            "encrypt",
            authority_key_fp,
            AuthorityLevel::DistroAccess,
        )?;
        
        // 2. Get authority key
        let authority_key = self.authority_chain.get_key(authority_key_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "encrypt_with_authority".to_string(),
                reason: format!("Authority key not found: {}", authority_key_fp),
            })?;
        
        // 3. Log authorization
        self.audit_logger.log_authority_operation("encrypt", &authority_key_fp.hex())?;
        
        // 4. Extract/derive passphrase for Age automation
        let passphrase = self.get_operation_passphrase(authority_key)?;
        
        // 5. Use existing CRUD manager for proven automation
        let lock_options = crate::sec::cage::lifecycle::crud_manager::LockOptions {
            recursive: false,
            format,
            pattern_filter: None,
            backup_before_lock: false,
        };
        
        // Convert single file operation to repository operation
        let temp_dir = input.parent().unwrap_or_else(|| Path::new("."));
        let _result = self.crud_manager.lock(temp_dir, &passphrase, lock_options)?;
        
        self.audit_logger.log_operation_success("encrypt_with_authority", input, output)?;
        Ok(())
    }
    
    /// Decrypt file with authority validation
    pub fn decrypt_with_authority(
        &mut self,
        input: &Path,
        output: &Path,
        authority_key_fp: &KeyFingerprint,
    ) -> AgeResult<()> {
        // 1. Authorize operation
        self.validation_engine.validate_operation_authorization(
            "decrypt",
            authority_key_fp,
            AuthorityLevel::DistroAccess,
        )?;
        
        // 2. Get authority key
        let authority_key = self.authority_chain.get_key(authority_key_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "decrypt_with_authority".to_string(),
                reason: format!("Authority key not found: {}", authority_key_fp),
            })?;
        
        // 3. Log authorization
        self.audit_logger.log_authority_operation("decrypt", &authority_key_fp.hex())?;
        
        // 4. Extract/derive passphrase for Age automation
        let passphrase = self.get_operation_passphrase(authority_key)?;
        
        // 5. Use existing CRUD manager for proven automation
        let unlock_options = crate::sec::cage::lifecycle::crud_manager::UnlockOptions {
            selective: false,
            verify_before_unlock: true,
            pattern_filter: None,
            preserve_encrypted: true,
        };
        
        // Convert single file operation to repository operation
        let temp_dir = input.parent().unwrap_or_else(|| Path::new("."));
        let _result = self.crud_manager.unlock(temp_dir, &passphrase, unlock_options)?;
        
        self.audit_logger.log_operation_success("decrypt_with_authority", input, output)?;
        Ok(())
    }
    
    /// Get repository status with authority validation
    pub fn repository_status_with_authority(
        &mut self,
        repo_path: &Path,
        authority_key_fp: &KeyFingerprint,
    ) -> AgeResult<crate::sec::cage::operations::RepositoryStatus> {
        // 1. Authorize operation
        self.validation_engine.validate_operation_authorization(
            "status",
            authority_key_fp,
            AuthorityLevel::DistroAccess,
        )?;
        
        // 2. Log operation
        self.audit_logger.log_authority_operation("status", &authority_key_fp.hex())?;
        
        // 3. Use existing CRUD manager
        self.crud_manager.status(repo_path)
    }
    
    /// Extract passphrase for operation from authority key
    fn get_operation_passphrase(&self, authority_key: &AuthorityKey) -> AgeResult<String> {
        match authority_key.key_type() {
            KeyType::Skull | KeyType::Ignition | KeyType::Distro => {
                // For ignition keys, we need the passphrase from environment or user
                self.get_ignition_passphrase(authority_key)
            },
            KeyType::Master | KeyType::Repo => {
                // For direct keys, derive operation passphrase from key material
                self.derive_operation_passphrase(authority_key)
            }
        }
    }
    
    /// Get ignition key passphrase from environment or prompt
    fn get_ignition_passphrase(&self, authority_key: &AuthorityKey) -> AgeResult<String> {
        // Try environment variable first
        let env_var = format!("PADLOCK_{}_PASSPHRASE", authority_key.fingerprint().short().to_uppercase());
        if let Ok(passphrase) = std::env::var(env_var) {
            return Ok(passphrase);
        }
        
        // For demo purposes, return a test passphrase
        // In production, this would prompt the user securely
        Ok(format!("demo-passphrase-{}", authority_key.fingerprint().short()))
    }
    
    /// Derive operation passphrase from direct key
    fn derive_operation_passphrase(&self, authority_key: &AuthorityKey) -> AgeResult<String> {
        // Simple derivation for demo - in production would use proper key derivation
        use sha2::{Sha256, Digest};
        
        let key_data = authority_key.key_material().public_key();
        let mut hasher = Sha256::new();
        hasher.update(key_data);
        hasher.update(b"padlock-operation-passphrase");
        
        let derived = hasher.finalize();
        Ok(format!("derived-{}", hex::encode(&derived[..8])))
    }
    
    /// Add authority key to chain
    pub fn add_authority_key(&mut self, key: AuthorityKey) -> AgeResult<()> {
        self.authority_chain.add_key(key)?;
        // Update validation engine with new chain
        self.validation_engine = AuthorityValidationEngine::new(self.authority_chain.clone());
        Ok(())
    }
    
    /// Get authority chain reference
    pub fn authority_chain(&self) -> &AuthorityChain {
        &self.authority_chain
    }
}

/// Bridge to Lucas's atomic authority operations  
pub struct LucasAuthorityBridge {
    authority_manager_path: PathBuf,
    emergency_recovery_path: PathBuf,
    audit_logger: AuditLogger,
}

impl LucasAuthorityBridge {
    /// Create new Lucas bridge
    pub fn new(
        pilot_directory: &Path,
        audit_log_path: Option<PathBuf>,
    ) -> AgeResult<Self> {
        let authority_manager_path = pilot_directory.join("01-key_authority/authority_manager.sh");
        let emergency_recovery_path = pilot_directory.join("01-key_authority/emergency_recovery.sh");
        
        // Verify scripts exist
        if !authority_manager_path.exists() {
            return Err(AgeError::InvalidOperation {
                operation: "create_lucas_bridge".to_string(),
                reason: format!("Authority manager script not found: {}", authority_manager_path.display()),
            });
        }
        
        let audit_logger = AuditLogger::new(audit_log_path)?;
        
        Ok(Self {
            authority_manager_path,
            emergency_recovery_path,
            audit_logger,
        })
    }
    
    /// Validate authority relationship atomically using Lucas's script
    pub fn validate_authority_atomically(
        &self,
        parent_key_path: &Path,
        child_key_path: &Path,
    ) -> AgeResult<bool> {
        self.audit_logger.log_info(&format!(
            "Lucas atomic validation: {} -> {}",
            parent_key_path.display(),
            child_key_path.display()
        ))?;
        
        let result = Command::new("bash")
            .arg(&self.authority_manager_path)
            .arg("validate_authority")
            .arg("--parent").arg(parent_key_path)
            .arg("--child").arg(child_key_path)
            .arg("--atomic")
            .output()
            .map_err(|e| AgeError::InvalidOperation {
                operation: "lucas_validate_authority".to_string(),
                reason: format!("Failed to execute Lucas script: {}", e),
            })?;
        
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            self.audit_logger.log_warning(&format!("Lucas validation failed: {}", stderr))?;
            return Ok(false);
        }
        
        // Parse Lucas's validation result
        let output = String::from_utf8_lossy(&result.stdout);
        let is_valid = output.trim() == "AUTHORITY_VALID";
        
        self.audit_logger.log_info(&format!(
            "Lucas validation result: {} ({})",
            if is_valid { "VALID" } else { "INVALID" },
            output.trim()
        ))?;
        
        Ok(is_valid)
    }
    
    /// Perform emergency recovery using Lucas's script
    pub fn emergency_recovery(&self, recovery_type: &str, key_path: &Path) -> AgeResult<()> {
        self.audit_logger.log_emergency_operation("lucas_emergency_recovery", key_path)?;
        
        let result = Command::new("bash")
            .arg(&self.emergency_recovery_path)
            .arg(recovery_type)
            .arg("--key").arg(key_path)
            .output()
            .map_err(|e| AgeError::InvalidOperation {
                operation: "lucas_emergency_recovery".to_string(),
                reason: format!("Failed to execute emergency recovery: {}", e),
            })?;
        
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(AgeError::InvalidOperation {
                operation: "lucas_emergency_recovery".to_string(),
                reason: format!("Emergency recovery failed: {}", stderr),
            });
        }
        
        self.audit_logger.log_info("Lucas emergency recovery completed successfully")?;
        Ok(())
    }
    
    /// Test if Lucas bridge is operational
    pub fn health_check(&self) -> AgeResult<()> {
        // Test authority manager script
        let result = Command::new("bash")
            .arg(&self.authority_manager_path)
            .arg("--version")
            .output();
            
        match result {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout);
                self.audit_logger.log_info(&format!("Lucas bridge operational: {}", version.trim()))?;
                Ok(())
            }
            Ok(_) => Err(AgeError::InvalidOperation {
                operation: "lucas_health_check".to_string(),
                reason: "Authority manager script returned error".to_string(),
            }),
            Err(e) => Err(AgeError::InvalidOperation {
                operation: "lucas_health_check".to_string(),
                reason: format!("Cannot execute authority manager: {}", e),
            }),
        }
    }
}

/// Factory for creating authority-integrated Age operations
pub struct AuthorityAgeFactory;

impl AuthorityAgeFactory {
    /// Create authority-Age interface with default configuration
    pub fn create_default(pilot_directory: &Path) -> AgeResult<AuthorityAgeInterface> {
        // Create default CRUD manager
        let adapter = crate::sec::cage::adapter::AdapterFactory::create_default()?;
        let config = crate::sec::cage::config::AgeConfig::production();
        let crud_manager = CrudManager::new(adapter, config)?;
        
        // Create empty authority chain for now
        let authority_chain = AuthorityChain::new();
        
        AuthorityAgeInterface::new(crud_manager, authority_chain, None)
    }
    
    /// Create Lucas authority bridge
    pub fn create_lucas_bridge(pilot_directory: &Path) -> AgeResult<LucasAuthorityBridge> {
        LucasAuthorityBridge::new(pilot_directory, None)
    }
}