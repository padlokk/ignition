//! Authority-based Age Encryption Operations
//!
//! Implements functional encryption operations using authority keys with real Age encryption.
//! Bridges the authority chain validation with actual file encryption operations.
//!
//! Security Guardian: Edgar - Real encryption operations with authority validation

use std::path::{Path, PathBuf};
use std::fs;
use tempfile::NamedTempFile;
use std::io::Write;

use crate::sec::cage::{
    error::{AgeError, AgeResult},
    tty_automation::TtyAutomator,
    config::OutputFormat,
    security::AuditLogger,
};
use super::super::{
    KeyType, AuthorityChain, AuthorityKey, KeyFingerprint,
    validation::AuthorityValidationEngine,
    ignition::IgnitionKey,
};

/// Authority-based Age encryption engine
pub struct AuthorityAgeEncryption {
    authority_chain: AuthorityChain,
    validation_engine: AuthorityValidationEngine,
    tty_automator: TtyAutomator,
    audit_logger: AuditLogger,
}

/// Encryption operation parameters
#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub authority_key: KeyFingerprint,
    pub output_format: OutputFormat,
    pub verify_authority: bool,
}

/// Encryption operation result
#[derive(Debug)]
pub struct EncryptionResult {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub authority_used: KeyFingerprint,
    pub recipients: Vec<String>,
    pub file_size_bytes: u64,
    pub success: bool,
}

impl AuthorityAgeEncryption {
    /// Create new authority-based encryption engine
    pub fn new(
        authority_chain: AuthorityChain,
        audit_log_path: Option<PathBuf>,
    ) -> AgeResult<Self> {
        let validation_engine = AuthorityValidationEngine::new(authority_chain.clone());
        let tty_automator = TtyAutomator::new()?;
        let audit_logger = AuditLogger::new(audit_log_path)?;
        
        Ok(Self {
            authority_chain,
            validation_engine,
            tty_automator,
            audit_logger,
        })
    }
    
    /// Encrypt file using authority key with validation
    pub fn encrypt_with_authority(
        &mut self,
        params: EncryptionParams,
    ) -> AgeResult<EncryptionResult> {
        self.audit_logger.log_operation_start("encrypt_with_authority", 
            &params.input_file, &params.output_file)?;
        
        // 1. Validate authority key exists and can perform encryption
        let authority_key = self.get_validated_authority_key(&params.authority_key)?;
        
        // 2. Validate operation authorization if requested
        if params.verify_authority {
            self.validate_encryption_authority(&authority_key)?;
        }
        
        // 3. Extract Age key material for encryption
        let age_recipients = self.extract_age_recipients_from_key(&authority_key)?;
        
        // 4. Perform Age encryption with TTY automation
        let encryption_success = self.perform_age_encryption(
            &params.input_file,
            &params.output_file,
            &age_recipients,
            params.output_format,
        )?;
        
        // 5. Verify encryption result
        let file_size = if encryption_success {
            fs::metadata(&params.output_file)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };
        
        let result = EncryptionResult {
            input_file: params.input_file,
            output_file: params.output_file.clone(),
            authority_used: params.authority_key,
            recipients: age_recipients,
            file_size_bytes: file_size,
            success: encryption_success && params.output_file.exists(),
        };
        
        if result.success {
            self.audit_logger.log_operation_success("encrypt_with_authority", 
                &result.input_file, &result.output_file)?;
        } else {
            self.audit_logger.log_operation_failure("encrypt_with_authority", 
                &result.input_file, &result.output_file,
                &AgeError::EncryptionFailed {
                    input: result.input_file.clone(),
                    output: result.output_file.clone(),
                    reason: "Age encryption failed".to_string(),
                })?;
        }
        
        Ok(result)
    }
    
    /// Decrypt file using authority key with validation
    pub fn decrypt_with_authority(
        &mut self,
        input_file: &Path,
        output_file: &Path,
        authority_key: &KeyFingerprint,
    ) -> AgeResult<EncryptionResult> {
        self.audit_logger.log_operation_start("decrypt_with_authority", 
            input_file, output_file)?;
        
        // 1. Get validated authority key
        let auth_key = self.get_validated_authority_key(authority_key)?;
        
        // 2. Extract Age secret key for decryption
        let age_secret_key = self.extract_age_secret_from_key(&auth_key)?;
        
        // 3. Create temporary key file for decryption
        let key_file = self.create_temp_age_key_file(&age_secret_key)?;
        
        // 4. Perform Age decryption with TTY automation
        let decryption_success = self.perform_age_decryption(
            input_file,
            output_file,
            key_file.path(),
        )?;
        
        // 5. Verify decryption result
        let file_size = if decryption_success {
            fs::metadata(output_file)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };
        
        let result = EncryptionResult {
            input_file: input_file.to_path_buf(),
            output_file: output_file.to_path_buf(),
            authority_used: authority_key.clone(),
            recipients: vec![age_secret_key],
            file_size_bytes: file_size,
            success: decryption_success && output_file.exists(),
        };
        
        if result.success {
            self.audit_logger.log_operation_success("decrypt_with_authority", 
                input_file, output_file)?;
        } else {
            self.audit_logger.log_operation_failure("decrypt_with_authority", 
                input_file, output_file,
                &AgeError::DecryptionFailed {
                    input: input_file.to_path_buf(),
                    output: output_file.to_path_buf(),
                    reason: "Age decryption failed".to_string(),
                })?;
        }
        
        Ok(result)
    }
    
    /// Encrypt file using ignition key with passphrase
    pub fn encrypt_with_ignition_key(
        &mut self,
        input_file: &Path,
        output_file: &Path,
        ignition_key: &mut IgnitionKey,
        passphrase: &str,
        output_format: OutputFormat,
    ) -> AgeResult<EncryptionResult> {
        self.audit_logger.log_operation_start("encrypt_with_ignition_key", 
            input_file, output_file)?;
        
        // 1. Unlock ignition key with passphrase
        let key_material = ignition_key.unlock(passphrase)?;
        
        // 2. Extract Age key from unlocked material
        let age_key = String::from_utf8(key_material.private_key().unwrap().to_vec())
            .map_err(|_| AgeError::InvalidOperation {
                operation: "extract_age_key".to_string(),
                reason: "Invalid Age key format in ignition key".to_string(),
            })?;
        
        // 3. Extract public key for recipient list
        let public_key = String::from_utf8(key_material.public_key().to_vec())
            .map_err(|_| AgeError::InvalidOperation {
                operation: "extract_age_public_key".to_string(),
                reason: "Invalid Age public key format".to_string(),
            })?;
        
        // 4. Perform encryption to self (using public key as recipient)
        let encryption_success = self.perform_age_encryption(
            input_file,
            output_file,
            &[public_key.clone()],
            output_format,
        )?;
        
        let file_size = if encryption_success {
            fs::metadata(output_file).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };
        
        let result = EncryptionResult {
            input_file: input_file.to_path_buf(),
            output_file: output_file.to_path_buf(),
            authority_used: ignition_key.fingerprint()?,
            recipients: vec![public_key],
            file_size_bytes: file_size,
            success: encryption_success && output_file.exists(),
        };
        
        if result.success {
            self.audit_logger.log_operation_success("encrypt_with_ignition_key", 
                input_file, output_file)?;
        } else {
            self.audit_logger.log_operation_failure("encrypt_with_ignition_key", 
                input_file, output_file,
                &AgeError::EncryptionFailed {
                    input: input_file.to_path_buf(),
                    output: output_file.to_path_buf(),
                    reason: "Ignition key encryption failed".to_string(),
                })?;
        }
        
        Ok(result)
    }
    
    /// Get validated authority key from chain
    fn get_validated_authority_key(&self, key_fp: &KeyFingerprint) -> AgeResult<&AuthorityKey> {
        self.authority_chain.get_key(key_fp)
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "get_authority_key".to_string(),
                reason: format!("Authority key not found: {}", key_fp),
            })
    }
    
    /// Validate authority can perform encryption operations
    fn validate_encryption_authority(&self, authority_key: &AuthorityKey) -> AgeResult<()> {
        // Only certain key types should perform encryption operations
        match authority_key.key_type() {
            KeyType::Skull | KeyType::Master | KeyType::Repo => {
                // High-level keys can encrypt
                Ok(())
            },
            KeyType::Ignition | KeyType::Distro => {
                // Lower-level keys need additional validation
                if authority_key.is_expired() {
                    return Err(AgeError::InvalidOperation {
                        operation: "validate_encryption_authority".to_string(),
                        reason: "Authority key has expired".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
    
    /// Extract Age recipients from authority key
    fn extract_age_recipients_from_key(&self, authority_key: &AuthorityKey) -> AgeResult<Vec<String>> {
        let key_material = authority_key.key_material();
        
        // Convert public key to Age recipient format
        let public_key_str = String::from_utf8(key_material.public_key().to_vec())
            .map_err(|_| AgeError::InvalidOperation {
                operation: "extract_age_recipients".to_string(),
                reason: "Invalid public key format".to_string(),
            })?;
        
        // Validate it's a proper Age public key
        if !public_key_str.starts_with("age1") {
            return Err(AgeError::InvalidOperation {
                operation: "extract_age_recipients".to_string(),
                reason: "Not a valid Age public key".to_string(),
            });
        }
        
        Ok(vec![public_key_str])
    }
    
    /// Extract Age secret key from authority key
    fn extract_age_secret_from_key(&self, authority_key: &AuthorityKey) -> AgeResult<String> {
        let key_material = authority_key.key_material();
        
        let secret_key = key_material.private_key()
            .ok_or_else(|| AgeError::InvalidOperation {
                operation: "extract_age_secret".to_string(),
                reason: "Authority key has no private key material".to_string(),
            })?;
        
        let secret_key_str = String::from_utf8(secret_key.to_vec())
            .map_err(|_| AgeError::InvalidOperation {
                operation: "extract_age_secret".to_string(),
                reason: "Invalid secret key format".to_string(),
            })?;
        
        // Validate it's a proper Age secret key
        if !secret_key_str.starts_with("AGE-SECRET-KEY-") {
            return Err(AgeError::InvalidOperation {
                operation: "extract_age_secret".to_string(),
                reason: "Not a valid Age secret key".to_string(),
            });
        }
        
        Ok(secret_key_str)
    }
    
    /// Create temporary Age key file for operations
    fn create_temp_age_key_file(&self, age_secret_key: &str) -> AgeResult<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()
            .map_err(|e| AgeError::TemporaryResourceError {
                resource_type: "key_file".to_string(),
                operation: "create".to_string(),
                reason: e.to_string(),
            })?;
        
        // Write Age key in proper format
        writeln!(temp_file, "{}", age_secret_key)
            .map_err(|e| AgeError::TemporaryResourceError {
                resource_type: "key_file".to_string(),
                operation: "write".to_string(),
                reason: e.to_string(),
            })?;
        
        Ok(temp_file)
    }
    
    /// Perform Age encryption with recipient list
    fn perform_age_encryption(
        &self,
        input_file: &Path,
        output_file: &Path,
        recipients: &[String],
        output_format: OutputFormat,
    ) -> AgeResult<bool> {
        // Create recipients file for Age
        let recipients_file = self.create_recipients_file(recipients)?;
        
        // Use TTY automation for Age encryption
        use std::process::{Command, Stdio};
        
        let mut age_cmd = vec!["age"];
        
        // Add recipients
        for recipient in recipients {
            age_cmd.extend(["-r", recipient]);
        }
        
        // Add output format if ASCII armor
        if matches!(output_format, OutputFormat::AsciiArmor) {
            age_cmd.push("-a");
        }
        
        // Add output file
        let output_path = output_file.to_string_lossy();
        age_cmd.extend(["-o", &output_path]);
        
        // Add input file
        let input_path = input_file.to_string_lossy();
        age_cmd.push(&input_path);
        
        let result = Command::new("age")
            .args(&age_cmd[1..]) // Skip first "age"
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| AgeError::ProcessExecutionFailed {
                command: "age".to_string(),
                exit_code: None,
                stderr: e.to_string(),
            })?;
        
        Ok(result.success() && output_file.exists())
    }
    
    /// Perform Age decryption with key file
    fn perform_age_decryption(
        &self,
        input_file: &Path,
        output_file: &Path,
        key_file: &Path,
    ) -> AgeResult<bool> {
        use std::process::{Command, Stdio};
        
        let result = Command::new("age")
            .arg("-d")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg(output_file)
            .arg(input_file)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| AgeError::ProcessExecutionFailed {
                command: "age -d".to_string(),
                exit_code: None,
                stderr: e.to_string(),
            })?;
        
        Ok(result.success() && output_file.exists())
    }
    
    /// Create temporary recipients file for Age
    fn create_recipients_file(&self, recipients: &[String]) -> AgeResult<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()
            .map_err(|e| AgeError::TemporaryResourceError {
                resource_type: "recipients_file".to_string(),
                operation: "create".to_string(),
                reason: e.to_string(),
            })?;
        
        for recipient in recipients {
            writeln!(temp_file, "{}", recipient)
                .map_err(|e| AgeError::TemporaryResourceError {
                    resource_type: "recipients_file".to_string(),
                    operation: "write".to_string(),
                    reason: e.to_string(),
                })?;
        }
        
        Ok(temp_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;
    
    #[test]
    fn test_authority_encryption_engine_creation() {
        let authority_chain = AuthorityChain::new();
        let engine = AuthorityAgeEncryption::new(authority_chain, None);
        assert!(engine.is_ok(), "Should create encryption engine successfully");
    }
}