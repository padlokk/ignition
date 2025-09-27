//! Ignite CLI entry point.
//!
//! Command-line interface for Ignition authority chain management.

use clap::{Parser, Subcommand};
use std::process;

use ignite::IgniteResult;
use ignite::ignite::authority::{KeyType, AuthorityKey, KeyMaterial, KeyFormat, KeyMetadata};

#[derive(Parser)]
#[command(name = "ignite")]
#[command(about = "Ignition authority chain management")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new authority key
    Create {
        /// Type of key to create (skull, master, repo, ignition, distro)
        #[arg(short, long)]
        key_type: String,

        /// Description for the key
        #[arg(short, long)]
        description: Option<String>,

        /// Parent key fingerprint for authority proof (optional)
        #[arg(short, long)]
        parent: Option<String>,
    },
    /// List authority keys
    List {
        /// Filter by key type
        #[arg(short, long)]
        key_type: Option<String>,
    },
    /// Show status of authority chain
    Status,
    /// Verify a proof or manifest file
    Verify {
        /// Path to proof or manifest file
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Create { key_type, description, parent } => {
            handle_create(&key_type, description.as_deref(), parent.as_deref())
        }
        Commands::List { key_type } => {
            handle_list(key_type.as_deref())
        }
        Commands::Status => {
            handle_status()
        }
        Commands::Verify { file } => {
            handle_verify(&file)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn handle_create(key_type: &str, description: Option<&str>, parent_fp_str: Option<&str>) -> IgniteResult<()> {
    use ignite::ignite::authority::{storage, proofs::{AuthorityClaim, ProofBundle}};
    use ignite::ignite::authority::KeyFingerprint;
    use ed25519_dalek::{SigningKey, SecretKey};
    use hub::random_ext::rand::{rng, Rng};
    use hub::time_ext::chrono::{Utc, Duration};

    let key_type = KeyType::from_str(key_type)?;
    println!("Creating {} key...", key_type.description());

    // Generate Ed25519 key material
    let mut random = rng();
    let secret_bytes: [u8; 32] = random.random();
    let secret_key = SecretKey::from(secret_bytes);
    let signing_key = SigningKey::from(&secret_key);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let private_key = Some(signing_key.to_bytes().to_vec());

    let key_material = KeyMaterial::new(public_key, private_key, KeyFormat::Ed25519);

    // Create metadata
    let mut metadata = KeyMetadata::default();
    metadata.creation_time = Utc::now();
    metadata.creator = whoami::username();
    metadata.description = description.unwrap_or("Created via CLI").to_string();

    // Create authority key
    let authority_key = AuthorityKey::new(key_material, key_type, None, Some(metadata))?;
    let child_fingerprint = authority_key.fingerprint().clone();

    // Save to storage
    let saved_path = storage::save_key(&authority_key)?;

    println!("✓ {} key created successfully", key_type.description());
    println!("  Fingerprint: {}", authority_key.fingerprint());
    println!("  Saved to: {}", saved_path.display());

    // Generate and save authority proof if parent specified
    if let Some(parent_fp_str) = parent_fp_str {
        let parent_fingerprint = KeyFingerprint::from_string(parent_fp_str)?;

        println!("\nGenerating authority proof...");

        // Load parent key - need to determine parent's key type from storage
        // For now, try loading from each key type until we find it
        let parent_key = {
            let mut found_key = None;
            for parent_type in [KeyType::Skull, KeyType::Master, KeyType::Repo, KeyType::Ignition, KeyType::Distro] {
                if let Ok(key) = storage::load_key(parent_type, &parent_fingerprint) {
                    found_key = Some(key);
                    break;
                }
            }
            found_key.ok_or_else(|| ignite::IgniteError::InvalidKey {
                reason: format!("Parent key not found with fingerprint: {}", parent_fingerprint),
            })?
        };

        // Validate parent can control child
        if !parent_key.can_control(key_type) {
            return Err(ignite::IgniteError::InvalidOperation {
                operation: "create_with_authority".to_string(),
                reason: format!("{} cannot control {}", parent_key.key_type().description(), key_type.description()),
            });
        }

        // Extract parent's signing key
        let parent_signing_key = {
            let private_key_bytes = parent_key.key_material().private_key()
                .ok_or_else(|| ignite::IgniteError::InvalidKey {
                    reason: "Parent key has no private key material".to_string(),
                })?;

            SigningKey::from_bytes(
                private_key_bytes.try_into()
                    .map_err(|_| ignite::IgniteError::InvalidKey {
                        reason: "Invalid parent key length".to_string(),
                    })?
            )
        };

        // Create and sign authority claim
        let claim = AuthorityClaim::new(
            parent_fingerprint.clone(),
            child_fingerprint.clone(),
            format!("Authority claim for {} key creation", key_type.description())
        );

        let expires_at = Utc::now() + Duration::hours(24);
        let proof = ProofBundle::sign_claim(&claim, &parent_signing_key, expires_at)?;

        // Save proof
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let proof_path = storage::save_proof(&proof, &parent_fingerprint, &timestamp)?;

        println!("✓ Authority proof generated and saved");
        println!("  Proof saved to: {}", proof_path.display());
        println!("  Expires at: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));

        // Update parent key to track this child relationship
        let mut parent_key_updated = parent_key;
        parent_key_updated.add_child(child_fingerprint)?;
        storage::save_key(&parent_key_updated)?;

        println!("✓ Parent-child relationship recorded");
    }

    Ok(())
}

fn handle_list(key_type_filter: Option<&str>) -> IgniteResult<()> {
    use ignite::ignite::authority::storage;

    if let Some(filter) = key_type_filter {
        let key_type = KeyType::from_str(filter)?;
        let keys = storage::list_keys(key_type)?;
        println!("Found {} {} keys:", keys.len(), key_type.description());
        for key_path in keys {
            println!("  {}", key_path.display());
        }
    } else {
        // List all key types
        for key_type in [KeyType::Skull, KeyType::Master, KeyType::Repo, KeyType::Ignition, KeyType::Distro] {
            let keys = storage::list_keys(key_type)?;
            if !keys.is_empty() {
                println!("{} keys ({})", key_type.description(), keys.len());
                for key_path in keys {
                    println!("  {}", key_path.display());
                }
            }
        }
    }

    Ok(())
}

fn handle_status() -> IgniteResult<()> {
    use ignite::ignite::{utils, authority::storage};

    println!("Ignition Authority Chain Status");
    println!("==============================");
    println!("Data root: {}", utils::data_root().display());
    println!();

    // Key counts by type
    println!("Authority Keys:");
    let mut total_keys = 0;
    for key_type in [KeyType::Skull, KeyType::Master, KeyType::Repo, KeyType::Ignition, KeyType::Distro] {
        let keys = storage::list_keys(key_type)?;
        let count = keys.len();
        total_keys += count;
        println!("  {} {}: {}",
                 if count > 0 { "✓" } else { "✗" },
                 key_type.description(),
                 count);
    }

    println!();
    println!("Total keys: {}", total_keys);

    if total_keys == 0 {
        println!();
        println!("No authority keys found. Use 'ignite create' to get started.");
    }

    Ok(())
}

fn handle_verify(file: &str) -> IgniteResult<()> {
    use std::path::Path;
    use std::fs;
    use ignite::IgniteError;
    use ignite::ignite::authority::proofs::ProofBundle;

    let path = Path::new(file);
    if !path.exists() {
        return Err(IgniteError::InvalidOperation {
            operation: "verify_file".to_string(),
            reason: format!("File '{}' does not exist", file),
        });
    }

    println!("Verifying file: {}", file);

    // Try to read the file
    let content = fs::read_to_string(path)
        .map_err(|e| IgniteError::InvalidOperation {
            operation: "read_file".to_string(),
            reason: format!("Failed to read file '{}': {}", file, e),
        })?;

    // Try to parse as ProofBundle first
    if let Ok(proof) = hub::data_ext::serde_json::from_str::<ProofBundle>(&content) {
        println!("✓ File is a valid proof bundle");
        println!("  Expires at: {}", proof.expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  Digest: {}", proof.digest);

        // Verify the proof
        match proof.verify() {
            Ok(()) => {
                println!("✓ Proof signature verification passed");

                // Try to parse the payload to show more details
                if let Ok(claim) = hub::data_ext::serde_json::from_str::<ignite::ignite::authority::proofs::AuthorityClaim>(&proof.payload_json) {
                    println!("\nAuthority Claim Details:");
                    println!("  Parent: {}", claim.parent_fp);
                    println!("  Child: {}", claim.child_fp);
                    println!("  Purpose: {}", claim.purpose);
                    println!("  Issued at: {}", claim.issued_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }

                return Ok(());
            }
            Err(e) => {
                return Err(IgniteError::InvalidOperation {
                    operation: "verify_proof".to_string(),
                    reason: format!("Proof verification failed: {}", e),
                });
            }
        }
    }

    // Try to parse as manifest
    if let Ok(manifest) = hub::data_ext::serde_json::from_str::<ignite::ignite::authority::manifests::AffectedKeyManifest>(&content) {
        println!("✓ File is a valid manifest");
        println!("  Schema version: {}", manifest.schema_version);
        println!("  Event type: {:?}", manifest.event.event_type);
        println!("  Parent fingerprint: {}", manifest.event.parent_fingerprint);
        println!("  Children count: {}", manifest.children.len());

        // Verify digest - this must succeed for verification to pass
        match manifest.verify_digest() {
            Ok(()) => {
                println!("✓ Digest verification passed");
                return Ok(());
            }
            Err(e) => {
                return Err(IgniteError::InvalidOperation {
                    operation: "verify_digest".to_string(),
                    reason: format!("Digest verification failed: {}", e),
                });
            }
        }
    }

    Err(IgniteError::InvalidOperation {
        operation: "parse_file".to_string(),
        reason: "File is not a valid proof or manifest".to_string(),
    })
}