//! Storage persistence for authority chain components.
//!
//! Handles atomic write operations and XDG-aware vault management for keys,
//! proofs, and manifests.

use hub::data_ext::serde_json;
use std::fs;
use std::path::{Path, PathBuf};

use super::chain::{AuthorityKey, KeyFingerprint, KeyType};
use super::manifests::AffectedKeyManifest;
use super::proofs::ProofBundle;
use crate::ignite::error::{IgniteError, Result};
use crate::ignite::utils;

/// Initialize vault directories
pub fn init_vault() -> Result<()> {
    utils::ensure_vault_dirs()
        .map_err(|e| IgniteError::io_error("init_vault", utils::data_root(), e))
}

/// Generate path for authority key storage
pub fn key_path(key_type: KeyType, fingerprint: &KeyFingerprint) -> PathBuf {
    utils::keys_dir()
        .join(key_type.to_string())
        .join(format!("{}.json", fingerprint.short()))
}

/// Generate path for proof storage
pub fn proof_path(fingerprint: &KeyFingerprint, timestamp: &str) -> PathBuf {
    utils::proofs_dir()
        .join(fingerprint.short())
        .join(format!("{}.json", timestamp))
}

/// Generate path for manifest storage (using manifest's own filename logic)
pub fn manifest_path(manifest: &AffectedKeyManifest) -> PathBuf {
    utils::manifests_dir().join(manifest.filename())
}

/// Atomic write helper - writes to temp file then renames
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| IgniteError::InvalidOperation {
        operation: "atomic_write".to_string(),
        reason: format!("Path has no parent: {:?}", path),
    })?;

    // Ensure parent directory exists
    fs::create_dir_all(parent)
        .map_err(|e| IgniteError::io_error("create_parent_dir", parent.to_path_buf(), e))?;

    // Write to temp file
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, data)
        .map_err(|e| IgniteError::io_error("write_temp", temp_path.clone(), e))?;

    // Atomic rename
    fs::rename(&temp_path, path)
        .map_err(|e| IgniteError::io_error("atomic_rename", path.to_path_buf(), e))?;

    Ok(())
}

/// Persist authority key to vault
pub fn save_key(key: &AuthorityKey) -> Result<PathBuf> {
    init_vault()?;

    let path = key_path(key.key_type(), key.fingerprint());
    let json = serde_json::to_string_pretty(key)
        .map_err(|e| IgniteError::crypto_error("serialize_key", e.to_string()))?;

    atomic_write(&path, json.as_bytes())?;
    Ok(path)
}

/// Load authority key from vault
pub fn load_key(key_type: KeyType, fingerprint: &KeyFingerprint) -> Result<AuthorityKey> {
    let path = key_path(key_type, fingerprint);
    let json = fs::read_to_string(&path)
        .map_err(|e| IgniteError::io_error("read_key", path.clone(), e))?;

    let mut key: AuthorityKey = serde_json::from_str(&json)
        .map_err(|e| IgniteError::crypto_error("deserialize_key", e.to_string()))?;

    key.set_key_path(path);
    Ok(key)
}

/// Persist proof bundle to vault
pub fn save_proof(
    proof: &ProofBundle,
    fingerprint: &KeyFingerprint,
    timestamp: &str,
) -> Result<PathBuf> {
    init_vault()?;

    let path = proof_path(fingerprint, timestamp);
    let json = serde_json::to_string_pretty(proof)
        .map_err(|e| IgniteError::crypto_error("serialize_proof", e.to_string()))?;

    atomic_write(&path, json.as_bytes())?;
    Ok(path)
}

/// Load proof bundle from vault
pub fn load_proof(fingerprint: &KeyFingerprint, timestamp: &str) -> Result<ProofBundle> {
    let path = proof_path(fingerprint, timestamp);
    let json = fs::read_to_string(&path)
        .map_err(|e| IgniteError::io_error("read_proof", path.clone(), e))?;

    serde_json::from_str(&json)
        .map_err(|e| IgniteError::crypto_error("deserialize_proof", e.to_string()))
}

/// Persist manifest to vault
pub fn save_manifest(manifest: &AffectedKeyManifest) -> Result<PathBuf> {
    init_vault()?;

    let path = manifest_path(manifest);

    // Use manifest's built-in JSON generation with digest
    let json = manifest
        .to_json_with_digest()
        .map_err(|e| IgniteError::crypto_error("serialize_manifest", e.to_string()))?;

    atomic_write(&path, json.as_bytes())?;
    Ok(path)
}

/// Load manifest from vault
pub fn load_manifest(parent_fp_short: &str, filename: &str) -> Result<AffectedKeyManifest> {
    let path = utils::manifests_dir().join(parent_fp_short).join(filename);

    let json = fs::read_to_string(&path)
        .map_err(|e| IgniteError::io_error("read_manifest", path.clone(), e))?;

    serde_json::from_str(&json)
        .map_err(|e| IgniteError::crypto_error("deserialize_manifest", e.to_string()))
}

/// List all keys of a given type
pub fn list_keys(key_type: KeyType) -> Result<Vec<PathBuf>> {
    let dir = utils::keys_dir().join(key_type.to_string());

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&dir).map_err(|e| IgniteError::io_error("list_keys", dir, e))?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| IgniteError::InvalidOperation {
            operation: "list_keys_entry".to_string(),
            reason: e.to_string(),
        })?;

        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            paths.push(entry.path());
        }
    }

    Ok(paths)
}

/// List all proofs for a given fingerprint
pub fn list_proofs(fingerprint: &KeyFingerprint) -> Result<Vec<PathBuf>> {
    let dir = utils::proofs_dir().join(fingerprint.short());

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&dir).map_err(|e| IgniteError::io_error("list_proofs", dir, e))?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| IgniteError::InvalidOperation {
            operation: "list_proofs_entry".to_string(),
            reason: e.to_string(),
        })?;

        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            paths.push(entry.path());
        }
    }

    Ok(paths)
}

/// List all manifests for a given parent fingerprint
pub fn list_manifests(parent_fp_short: &str) -> Result<Vec<PathBuf>> {
    let dir = utils::manifests_dir().join(parent_fp_short);

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries =
        fs::read_dir(&dir).map_err(|e| IgniteError::io_error("list_manifests", dir, e))?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| IgniteError::InvalidOperation {
            operation: "list_manifests_entry".to_string(),
            reason: e.to_string(),
        })?;

        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            paths.push(entry.path());
        }
    }

    Ok(paths)
}

// TODO: Implement key deletion with archival
// TODO: Implement proof archival during rotation
// TODO: Add integrity verification on load (hash checking)
// TODO: Add encryption at rest for private key material (via Cage)
// TODO: Implement backup/restore functionality

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignite::authority::chain::{KeyFormat, KeyMaterial, KeyType};
    use crate::ignite::authority::manifests::{
        AffectedKeyManifest, ManifestChild, ManifestEvent, ManifestEventType,
    };
    use crate::ignite::authority::proofs::{AuthorityClaim, ProofBundle};
    use ed25519_dalek::{SecretKey, SigningKey};
    use hub::random_ext::rand::{rng, Rng};
    use hub::time_ext::chrono::{Duration, Utc};
    use serial_test::serial;
    use std::env;
    use tempfile::TempDir;

    struct TestEnvironment {
        _temp_dir: TempDir,
    }

    impl TestEnvironment {
        fn new() -> Self {
            let temp_dir = TempDir::new().unwrap();
            env::set_var("IGNITE_DATA_ROOT", temp_dir.path());
            Self {
                _temp_dir: temp_dir,
            }
        }
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            env::remove_var("IGNITE_DATA_ROOT");
        }
    }

    fn create_test_key_material() -> KeyMaterial {
        let mut random = rng();
        let secret_bytes: [u8; 32] = random.random();
        let secret_key = SecretKey::from(secret_bytes);
        let signing_key = SigningKey::from(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_key = Some(signing_key.to_bytes().to_vec());

        KeyMaterial::new(public_key, private_key, KeyFormat::Ed25519)
    }

    fn create_test_authority_key() -> AuthorityKey {
        let key_material = create_test_key_material();
        AuthorityKey::new(key_material, KeyType::Master, None, None).unwrap()
    }

    fn create_test_authority_key_with_type(key_type: KeyType) -> AuthorityKey {
        let key_material = create_test_key_material();
        AuthorityKey::new(key_material, key_type, None, None).unwrap()
    }

    #[test]
    #[serial]
    fn test_key_storage_round_trip() {
        let _test_env = TestEnvironment::new();
        let original_key = create_test_authority_key();

        // Save the key
        let saved_path = save_key(&original_key).unwrap();
        assert!(saved_path.exists());

        // Load the key back
        let loaded_key = load_key(original_key.key_type(), original_key.fingerprint()).unwrap();

        // Verify they match
        assert_eq!(loaded_key.key_type(), original_key.key_type());
        assert_eq!(loaded_key.fingerprint(), original_key.fingerprint());
        assert_eq!(
            loaded_key.key_material().public_key(),
            original_key.key_material().public_key()
        );
        assert_eq!(
            loaded_key.key_material().private_key(),
            original_key.key_material().private_key()
        );
    }

    #[test]
    #[serial]
    fn test_proof_storage_round_trip() {
        let _test_env = TestEnvironment::new();
        let signing_key = {
            let mut random = rng();
            let secret_bytes: [u8; 32] = random.random();
            let secret_key = SecretKey::from(secret_bytes);
            SigningKey::from(&secret_key)
        };

        let parent_fp = KeyFingerprint::from_string("SHA256:parent123").unwrap();
        let child_fp = KeyFingerprint::from_string("SHA256:child456").unwrap();
        let expires_at = Utc::now() + Duration::hours(1);

        let claim = AuthorityClaim::new(parent_fp.clone(), child_fp, "test storage");
        let original_proof = ProofBundle::sign_claim(&claim, &signing_key, expires_at).unwrap();

        // Save the proof
        let timestamp = "2024-01-01T12-00-00Z";
        let saved_path = save_proof(&original_proof, &parent_fp, timestamp).unwrap();
        assert!(saved_path.exists());

        // Load the proof back
        let loaded_proof = load_proof(&parent_fp, timestamp).unwrap();

        // Verify they match
        assert_eq!(loaded_proof.payload_json, original_proof.payload_json);
        assert_eq!(loaded_proof.digest, original_proof.digest);
        assert_eq!(loaded_proof.signature, original_proof.signature);
        assert_eq!(loaded_proof.public_key, original_proof.public_key);
        assert_eq!(loaded_proof.expires_at, original_proof.expires_at);

        // Verify the loaded proof is still valid
        assert!(loaded_proof.verify_full().is_ok());
    }

    #[test]
    #[serial]
    fn test_manifest_storage_round_trip() {
        let _test_env = TestEnvironment::new();
        let parent_fp = KeyFingerprint::from_string("SHA256:parent123").unwrap();
        let child_fp = KeyFingerprint::from_string("SHA256:child456").unwrap();

        let event = ManifestEvent::new(
            ManifestEventType::Rotation,
            parent_fp,
            "Test storage rotation",
        );

        let mut original_manifest = AffectedKeyManifest::new(event);
        let child = ManifestChild::new(child_fp, KeyType::Ignition, "active", Utc::now());
        original_manifest.add_child(child);
        original_manifest.compute_digest().unwrap();

        // Save the manifest
        let saved_path = save_manifest(&original_manifest).unwrap();
        assert!(saved_path.exists());

        // Load the manifest back by parsing the filename
        let filename = saved_path.file_name().unwrap().to_str().unwrap();
        let parent_short = original_manifest.event.parent_fingerprint.short();
        let loaded_manifest = load_manifest(&parent_short, filename).unwrap();

        // Verify they match
        assert_eq!(
            loaded_manifest.schema_version,
            original_manifest.schema_version
        );
        assert_eq!(
            loaded_manifest.event.event_type,
            original_manifest.event.event_type
        );
        assert_eq!(
            loaded_manifest.event.parent_fingerprint,
            original_manifest.event.parent_fingerprint
        );
        assert_eq!(
            loaded_manifest.children.len(),
            original_manifest.children.len()
        );
        assert_eq!(
            loaded_manifest.children[0].fingerprint,
            original_manifest.children[0].fingerprint
        );

        // Verify digest integrity
        assert!(loaded_manifest.verify_digest().is_ok());
    }

    #[test]
    #[serial]
    fn test_list_keys() {
        let _test_env = TestEnvironment::new();

        // Save multiple keys of different types
        let master_key = create_test_authority_key_with_type(KeyType::Master);
        let repo_key = create_test_authority_key_with_type(KeyType::Repo);

        save_key(&master_key).unwrap();
        save_key(&repo_key).unwrap();

        // List master keys
        let master_keys = list_keys(KeyType::Master).unwrap();
        assert_eq!(master_keys.len(), 1);

        // List repo keys
        let repo_keys = list_keys(KeyType::Repo).unwrap();
        assert_eq!(repo_keys.len(), 1);

        // List skull keys (should be empty)
        let skull_keys = list_keys(KeyType::Skull).unwrap();
        assert_eq!(skull_keys.len(), 0);
    }

    #[test]
    #[serial]
    fn test_atomic_write_safety() {
        let _test_env = TestEnvironment::new();
        let test_path = utils::data_root().join("test_atomic.json");
        let test_data = b"test data";

        // Write data atomically
        atomic_write(&test_path, test_data).unwrap();
        assert!(test_path.exists());

        // Verify content
        let read_data = fs::read(&test_path).unwrap();
        assert_eq!(read_data, test_data);

        // Verify temp file was cleaned up
        let temp_path = test_path.with_extension("tmp");
        assert!(!temp_path.exists());
    }

    #[test]
    #[serial]
    fn test_init_vault_creates_directories() {
        let _test_env = TestEnvironment::new();

        init_vault().unwrap();

        assert!(utils::keys_dir().exists());
        assert!(utils::proofs_dir().exists());
        assert!(utils::manifests_dir().exists());
        assert!(utils::metadata_dir().exists());
    }

    #[test]
    fn test_path_generation() {
        let fingerprint = KeyFingerprint::from_string("SHA256:abcdef123456").unwrap();

        // Test key path generation
        let key_path = key_path(KeyType::Master, &fingerprint);
        assert!(key_path.to_string_lossy().contains("keys"));
        assert!(key_path.to_string_lossy().contains("master"));
        assert!(key_path.to_string_lossy().ends_with("abcdef12.json"));

        // Test proof path generation
        let proof_path = proof_path(&fingerprint, "2024-01-01T12-00-00Z");
        assert!(proof_path.to_string_lossy().contains("proofs"));
        assert!(proof_path.to_string_lossy().contains("abcdef12"));
        assert!(proof_path
            .to_string_lossy()
            .ends_with("2024-01-01T12-00-00Z.json"));
    }
}
