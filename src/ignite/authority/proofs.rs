//! Authority proof generation and verification.
//!
//! Implements Ed25519 signature-based proofs for authority claims and subject receipts
//! per IGNITE_PROOFS.md specification.

use hub::time_ext::chrono::{DateTime, Utc};
use hub::data_ext::serde::{Deserialize, Serialize};
use hub::random_ext::rand::{Rng, rng};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ignite::error::{IgniteError, Result};
use super::chain::KeyFingerprint;


//corrective
// pub struct ProofEngine;

// impl ProofEngine {
//     pub fn new() -> Self {
//         Self
//     }
// }


/// Authority claim payload (parent asserting control over child)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityClaim {
    pub schema_version: String,
    pub parent_fp: KeyFingerprint,
    pub child_fp: KeyFingerprint,
    pub issued_at: DateTime<Utc>,
    pub purpose: String,
    pub nonce: String,
}

impl AuthorityClaim {
    pub fn new(
        parent_fp: KeyFingerprint,
        child_fp: KeyFingerprint,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            parent_fp,
            child_fp,
            issued_at: Utc::now(),
            purpose: purpose.into(),
            nonce: Self::generate_nonce(),
        }
    }

    fn generate_nonce() -> String {
        let mut random = rng();
        let random_bytes: [u8; 16] = random.random();
        random_bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Serialize to canonical JSON for signing
    pub fn to_canonical_json(&self) -> Result<String> {
        // TODO: Implement proper canonical JSON with sorted keys
        // For now, manually construct in sorted order per spec
        Ok(format!(
            r#"{{"child_fp":"{}","issued_at":"{}","nonce":"{}","parent_fp":"{}","purpose":"{}","schema_version":"{}"}}"#,
            self.child_fp,
            self.issued_at.to_rfc3339(),
            self.nonce,
            self.parent_fp,
            self.purpose,
            self.schema_version
        ))
    }

    /// Compute SHA256 digest of canonical payload
    pub fn compute_digest(&self) -> Result<String> {
        let canonical = self.to_canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Subject receipt payload (child acknowledging parent's authority)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectReceipt {
    pub schema_version: String,
    pub child_fp: KeyFingerprint,
    pub parent_fp: KeyFingerprint,
    pub acknowledged_at: DateTime<Utc>,
    pub nonce: String,
}

impl SubjectReceipt {
    pub fn new(child_fp: KeyFingerprint, parent_fp: KeyFingerprint) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            child_fp,
            parent_fp,
            acknowledged_at: Utc::now(),
            nonce: Self::generate_nonce(),
        }
    }

    fn generate_nonce() -> String {
        let mut random = rng();
        let random_bytes: [u8; 16] = random.random();
        random_bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Serialize to canonical JSON for signing
    pub fn to_canonical_json(&self) -> Result<String> {
        Ok(format!(
            r#"{{"acknowledged_at":"{}","child_fp":"{}","nonce":"{}","parent_fp":"{}","schema_version":"{}"}}"#,
            self.acknowledged_at.to_rfc3339(),
            self.child_fp,
            self.nonce,
            self.parent_fp,
            self.schema_version
        ))
    }

    /// Compute SHA256 digest of canonical payload
    pub fn compute_digest(&self) -> Result<String> {
        let canonical = self.to_canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Complete proof bundle with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub payload_json: String,
    pub digest: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

impl ProofBundle {
    /// Sign an authority claim with Ed25519 private key
    pub fn sign_claim(
        claim: &AuthorityClaim,
        signing_key: &SigningKey,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let payload_json = claim.to_canonical_json()?;
        let digest = claim.compute_digest()?;

        let signature = signing_key.sign(digest.as_bytes());
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        Ok(Self {
            payload_json,
            digest,
            signature: signature.to_bytes().to_vec(),
            public_key,
            expires_at,
        })
    }

    /// Sign a subject receipt with Ed25519 private key
    pub fn sign_receipt(
        receipt: &SubjectReceipt,
        signing_key: &SigningKey,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let payload_json = receipt.to_canonical_json()?;
        let digest = receipt.compute_digest()?;

        let signature = signing_key.sign(digest.as_bytes());
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        Ok(Self {
            payload_json,
            digest,
            signature: signature.to_bytes().to_vec(),
            public_key,
            expires_at,
        })
    }

    /// Verify signature and expiration
    pub fn verify(&self) -> Result<()> {
        if Utc::now() > self.expires_at {
            return Err(IgniteError::CryptoError {
                operation: "verify_proof".to_string(),
                reason: "Proof has expired".to_string(),
            });
        }

        let public_key = VerifyingKey::from_bytes(
            self.public_key
                .as_slice()
                .try_into()
                .map_err(|_| IgniteError::crypto_error("parse_public_key", "Invalid key length"))?,
        )
        .map_err(|e| IgniteError::crypto_error("parse_public_key", e.to_string()))?;

        let signature = Signature::from_bytes(
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| IgniteError::crypto_error("parse_signature", "Invalid signature length"))?,
        );

        public_key
            .verify(self.digest.as_bytes(), &signature)
            .map_err(|e| IgniteError::crypto_error("verify_signature", e.to_string()))?;

        Ok(())
    }

    /// Recompute digest from payload and verify it matches
    pub fn verify_digest(&self) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(self.payload_json.as_bytes());
        let computed = format!("{:x}", hasher.finalize());

        if computed != self.digest {
            return Err(IgniteError::CryptoError {
                operation: "verify_digest".to_string(),
                reason: "Digest mismatch - payload may have been tampered with".to_string(),
            });
        }

        Ok(())
    }

    /// Full verification: digest + signature + expiration
    pub fn verify_full(&self) -> Result<()> {
        self.verify_digest()?;
        self.verify()?;
        Ok(())
    }
}

// TODO: Implement proof storage/persistence to vault
// TODO: Implement proof rotation scheduler (renew 12h before expires_at)
// TODO: Integrate with authority chain for automatic proof generation during operations
// TODO: Add archival logic for old proofs during rotation
// TODO: Implement CLI command `ignite proof --verify <file>` handler

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, SecretKey};
    use hub::random_ext::rand::{rng, Rng};

    fn create_test_signing_key() -> SigningKey {
        let mut random = rng();
        let secret_bytes: [u8; 32] = random.random();
        let secret_key = SecretKey::from(secret_bytes);
        SigningKey::from(&secret_key)
    }

    fn create_test_fingerprint(suffix: &str) -> KeyFingerprint {
        KeyFingerprint::from_string(&format!("SHA256:test{}", suffix)).unwrap()
    }

    #[test]
    fn test_authority_claim_creation() {
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");

        let claim = AuthorityClaim::new(
            parent_fp.clone(),
            child_fp.clone(),
            "test purpose",
        );

        assert_eq!(claim.parent_fp, parent_fp);
        assert_eq!(claim.child_fp, child_fp);
        assert_eq!(claim.purpose, "test purpose");
        assert_eq!(claim.schema_version, "1.0");
        assert!(!claim.nonce.is_empty());
        assert_eq!(claim.nonce.len(), 32); // 16 bytes * 2 hex chars
    }

    #[test]
    fn test_authority_claim_nonce_uniqueness() {
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");

        let claim1 = AuthorityClaim::new(parent_fp.clone(), child_fp.clone(), "test");
        let claim2 = AuthorityClaim::new(parent_fp, child_fp, "test");

        // Nonces should be different for different claims
        assert_ne!(claim1.nonce, claim2.nonce);
    }

    #[test]
    fn test_authority_claim_canonical_json() {
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");

        let claim = AuthorityClaim::new(parent_fp, child_fp, "test purpose");
        let json = claim.to_canonical_json().unwrap();

        // Check that JSON contains expected fields in sorted order
        assert!(json.contains("\"child_fp\""));
        assert!(json.contains("\"parent_fp\""));
        assert!(json.contains("\"purpose\":\"test purpose\""));
        assert!(json.contains("\"schema_version\":\"1.0\""));
        assert!(json.contains("\"nonce\""));
    }

    #[test]
    fn test_subject_receipt_creation() {
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");

        let receipt = SubjectReceipt::new(child_fp.clone(), parent_fp.clone());

        assert_eq!(receipt.child_fp, child_fp);
        assert_eq!(receipt.parent_fp, parent_fp);
        assert_eq!(receipt.schema_version, "1.0");
        assert!(!receipt.nonce.is_empty());
        assert_eq!(receipt.nonce.len(), 32); // 16 bytes * 2 hex chars
    }

    #[test]
    fn test_proof_bundle_sign_and_verify_claim() {
        let signing_key = create_test_signing_key();
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");
        let expires_at = Utc::now() + hub::time_ext::chrono::Duration::hours(1);

        let claim = AuthorityClaim::new(parent_fp, child_fp, "test authority claim");

        // Sign the claim
        let proof = ProofBundle::sign_claim(&claim, &signing_key, expires_at).unwrap();

        // Verify the proof
        assert!(proof.verify_full().is_ok());
        assert!(proof.verify_digest().is_ok());
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_bundle_sign_and_verify_receipt() {
        let signing_key = create_test_signing_key();
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");
        let expires_at = Utc::now() + hub::time_ext::chrono::Duration::hours(1);

        let receipt = SubjectReceipt::new(child_fp, parent_fp);

        // Sign the receipt
        let proof = ProofBundle::sign_receipt(&receipt, &signing_key, expires_at).unwrap();

        // Verify the proof
        assert!(proof.verify_full().is_ok());
        assert!(proof.verify_digest().is_ok());
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_bundle_expiration() {
        let signing_key = create_test_signing_key();
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");
        let expires_at = Utc::now() - hub::time_ext::chrono::Duration::seconds(1); // Already expired

        let claim = AuthorityClaim::new(parent_fp, child_fp, "expired claim");
        let proof = ProofBundle::sign_claim(&claim, &signing_key, expires_at).unwrap();

        // Verification should fail due to expiration
        assert!(proof.verify().is_err());
        assert!(proof.verify_full().is_err());

        // But digest verification should still work
        assert!(proof.verify_digest().is_ok());
    }

    #[test]
    fn test_proof_bundle_tampered_digest() {
        let signing_key = create_test_signing_key();
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");
        let expires_at = Utc::now() + hub::time_ext::chrono::Duration::hours(1);

        let claim = AuthorityClaim::new(parent_fp, child_fp, "test claim");
        let mut proof = ProofBundle::sign_claim(&claim, &signing_key, expires_at).unwrap();

        // Tamper with the payload
        proof.payload_json = proof.payload_json.replace("test claim", "tampered claim");

        // Digest verification should fail
        assert!(proof.verify_digest().is_err());
        assert!(proof.verify_full().is_err());
    }

    #[test]
    fn test_digest_computation_deterministic() {
        let parent_fp = create_test_fingerprint("parent");
        let child_fp = create_test_fingerprint("child");

        let claim1 = AuthorityClaim::new(parent_fp.clone(), child_fp.clone(), "test");
        let claim2 = AuthorityClaim {
            schema_version: claim1.schema_version.clone(),
            parent_fp: claim1.parent_fp.clone(),
            child_fp: claim1.child_fp.clone(),
            issued_at: claim1.issued_at,
            purpose: claim1.purpose.clone(),
            nonce: claim1.nonce.clone(),
        };

        let digest1 = claim1.compute_digest().unwrap();
        let digest2 = claim2.compute_digest().unwrap();

        // Same claim data should produce same digest
        assert_eq!(digest1, digest2);
    }
}
