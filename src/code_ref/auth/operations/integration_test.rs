//! Integration Test for Complete Authority Chain Operations
//!
//! Tests the end-to-end functionality of the authority chain system

#[cfg(test)]
mod tests {
    use super::super::super::{
        KeyType, AuthorityChain,
        operations::{AuthorityAgeKeyGenerator, AuthorityAgeEncryption, EncryptionParams},
        ignition::IgnitionKey,
    };
    use crate::sec::cage::config::OutputFormat;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_complete_authority_chain_workflow() {
        println!("\n🔥 TESTING COMPLETE AUTHORITY CHAIN WORKFLOW");
        println!("=============================================");
        
        // Create test environment
        let test_dir = TempDir::new().expect("Should create test dir");
        let keys_dir = test_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("Should create keys dir");
        
        println!("📁 Test Directory: {}", test_dir.path().display());
        
        // Phase 1: Generate Authority Chain
        println!("\n🔑 Generating X->M->R->I->D Authority Chain...");
        let authority_chain = AuthorityChain::new();
        let mut key_generator = AuthorityAgeKeyGenerator::new(authority_chain, None)
            .expect("Should create key generator");
        
        let generated_keys = key_generator.generate_complete_authority_chain("test", &keys_dir)
            .expect("Should generate complete authority chain");
        
        assert_eq!(generated_keys.len(), 5, "Should generate 5 keys");
        println!("✅ Generated {} authority keys", generated_keys.len());
        
        // Verify we have all key types
        let key_types: Vec<KeyType> = generated_keys.iter()
            .map(|k| k.authority_key.key_type())
            .collect();
        assert!(key_types.contains(&KeyType::Skull));
        assert!(key_types.contains(&KeyType::Master));
        assert!(key_types.contains(&KeyType::Repo));
        assert!(key_types.contains(&KeyType::Ignition));
        assert!(key_types.contains(&KeyType::Distro));
        
        // Phase 2: File Encryption with Authority Key
        println!("\n🔐 Testing File Encryption with Authority Key...");
        let test_content = "Secret data for authority chain test!";
        let input_file = test_dir.path().join("secret.txt");
        let encrypted_file = test_dir.path().join("secret.age");
        let decrypted_file = test_dir.path().join("secret_decrypted.txt");
        
        fs::write(&input_file, test_content).expect("Should write test file");
        
        // Get master key for encryption
        let master_key = generated_keys.iter()
            .find(|k| k.authority_key.key_type() == KeyType::Master)
            .expect("Should have master key");
        
        let mut encryption_engine = AuthorityAgeEncryption::new(
            key_generator.authority_chain.clone(),
            None
        ).expect("Should create encryption engine");
        
        // Encrypt with master authority key
        let encryption_params = EncryptionParams {
            input_file: input_file.clone(),
            output_file: encrypted_file.clone(),
            authority_key: master_key.authority_key.fingerprint().clone(),
            output_format: OutputFormat::Binary,
            verify_authority: true,
        };
        
        let encrypt_result = encryption_engine.encrypt_with_authority(encryption_params)
            .expect("Should encrypt with authority key");
        
        assert!(encrypt_result.success, "Encryption should succeed");
        assert!(encrypted_file.exists(), "Encrypted file should exist");
        println!("✅ Encryption successful: {} bytes", encrypt_result.file_size_bytes);
        
        // Decrypt with master authority key
        let decrypt_result = encryption_engine.decrypt_with_authority(
            &encrypted_file,
            &decrypted_file,
            &master_key.authority_key.fingerprint(),
        ).expect("Should decrypt with authority key");
        
        assert!(decrypt_result.success, "Decryption should succeed");
        assert!(decrypted_file.exists(), "Decrypted file should exist");
        
        // Verify content matches
        let decrypted_content = fs::read_to_string(&decrypted_file)
            .expect("Should read decrypted file");
        assert_eq!(decrypted_content, test_content, "Content should match original");
        println!("✅ Decryption successful and content verified");
        
        // Phase 3: Ignition Key Workflow
        println!("\n🚀 Testing Ignition Key Workflow...");
        let ignition_auth_key = generated_keys.iter()
            .find(|k| k.authority_key.key_type() == KeyType::Ignition)
            .expect("Should have ignition key");
        
        let ignition_passphrase = "TestIgnitionPass123!";
        let mut ignition_key = IgnitionKey::create(
            ignition_auth_key.authority_key.key_material(),
            KeyType::Ignition,
            ignition_passphrase,
            None,
            Some("test-ignition".to_string()),
        ).expect("Should create ignition key");
        
        let ignition_input = test_dir.path().join("ignition_test.txt");
        let ignition_encrypted = test_dir.path().join("ignition_test.age");
        let ignition_content = "Ignition key test data!";
        
        fs::write(&ignition_input, ignition_content).expect("Should write ignition test file");
        
        let ignition_result = encryption_engine.encrypt_with_ignition_key(
            &ignition_input,
            &ignition_encrypted,
            &mut ignition_key,
            ignition_passphrase,
            OutputFormat::Binary,
        ).expect("Should encrypt with ignition key");
        
        assert!(ignition_result.success, "Ignition key encryption should succeed");
        assert!(ignition_encrypted.exists(), "Ignition encrypted file should exist");
        println!("✅ Ignition key encryption successful");
        
        // Phase 4: Authority Chain Validation
        println!("\n🔍 Testing Authority Chain Validation...");
        let validation_engine = &mut key_generator.validation_engine;
        
        // Test Skull -> Master authority
        let skull_key = generated_keys.iter()
            .find(|k| k.authority_key.key_type() == KeyType::Skull)
            .expect("Should have skull key");
        
        let authority_valid = validation_engine.test_authority(
            skull_key.authority_key.fingerprint(),
            master_key.authority_key.fingerprint(),
        ).expect("Should test authority");
        
        assert!(authority_valid, "Skull should have authority over Master");
        println!("✅ Authority validation working");
        
        println!("\n🎉 COMPLETE WORKFLOW TEST: SUCCESS!");
        println!("✅ Authority Chain Generation: WORKING");
        println!("✅ File Encryption/Decryption: WORKING"); 
        println!("✅ Ignition Key Workflow: WORKING");
        println!("✅ Authority Validation: WORKING");
        println!("🏆 X->M->R->I->D AUTHORITY CHAIN IS FULLY FUNCTIONAL!");
    }
}