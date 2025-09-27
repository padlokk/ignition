//! Affected-key manifest generation and serialization.
//!
//! Implements manifest tracking for rotation/revocation events per IGNITE_MANIFEST.md.
//! Manifests record descendants invalidated by authority operations to enable
//! downstream automation.

use hub::time_ext::chrono::{DateTime, Utc};
use hub::data_ext::serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ignite::error::{IgniteError, Result};
use super::chain::{KeyFingerprint, KeyType};


//corrective
// pub struct Manifest;

// impl Manifest {
//     pub fn new() -> Self {
//         Self
//     }
// }



/// Type of manifest event
#[derive(Debug, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ManifestEventType {
    Rotation,
    Revocation,
}

impl From<ManifestEventType> for String {
    fn from(event_type: ManifestEventType) -> String {
        match event_type {
            ManifestEventType::Rotation => "rotation".to_string(),
            ManifestEventType::Revocation => "revocation".to_string(),
        }
    }
}

impl TryFrom<String> for ManifestEventType {
    type Error = IgniteError;

    fn try_from(s: String) -> Result<Self> {
        match s.as_str() {
            "rotation" => Ok(ManifestEventType::Rotation),
            "revocation" => Ok(ManifestEventType::Revocation),
            _ => Err(IgniteError::InvalidOperation {
                operation: "parse_event_type".to_string(),
                reason: format!("Unknown event type: {}", s),
            }),
        }
    }
}

impl ManifestEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::Revocation => "revocation",
        }
    }
}

/// Event metadata for a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEvent {
    pub event_type: ManifestEventType,
    pub parent_fingerprint: KeyFingerprint,
    pub initiated_at: DateTime<Utc>,
    pub initiated_by: String,
    pub reason: String,
}

impl ManifestEvent {
    pub fn new(
        event_type: ManifestEventType,
        parent_fingerprint: KeyFingerprint,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            parent_fingerprint,
            initiated_at: Utc::now(),
            initiated_by: "ignite-cli".to_string(),
            reason: reason.into(),
        }
    }
}

/// Digest metadata for manifest integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDigest {
    pub algorithm: String,
    pub value: String,
    pub manifest_body: String,
}

impl ManifestDigest {
    pub fn compute(canonical_json: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let hash = hasher.finalize();

        Self {
            algorithm: "SHA256".to_string(),
            value: format!("{:x}", hash),
            manifest_body: "canonical".to_string(),
        }
    }
}

/// Scope metadata for affected keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestScope {
    pub paths: Vec<String>,
    pub env: String,
}

impl ManifestScope {
    pub fn new(paths: Vec<String>, env: impl Into<String>) -> Self {
        Self {
            paths,
            env: env.into(),
        }
    }
}

/// Single affected child key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestChild {
    pub fingerprint: KeyFingerprint,
    pub role: KeyType,
    pub status: String,
    pub ciphertext_md5: Option<String>,
    pub scope: Option<ManifestScope>,
    pub issued_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ManifestChild {
    pub fn new(
        fingerprint: KeyFingerprint,
        role: KeyType,
        status: impl Into<String>,
        issued_at: DateTime<Utc>,
    ) -> Self {
        Self {
            fingerprint,
            role,
            status: status.into(),
            ciphertext_md5: None,
            scope: None,
            issued_at,
            revoked_at: None,
        }
    }

    pub fn with_revocation(mut self, revoked_at: DateTime<Utc>) -> Self {
        self.revoked_at = Some(revoked_at);
        self
    }

    pub fn with_scope(mut self, scope: ManifestScope) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn with_ciphertext_md5(mut self, md5: String) -> Self {
        self.ciphertext_md5 = Some(md5);
        self
    }
}

/// Complete affected-key manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedKeyManifest {
    pub schema_version: String,
    pub event: ManifestEvent,
    pub digest: Option<ManifestDigest>,
    pub children: Vec<ManifestChild>,
}

impl AffectedKeyManifest {
    pub fn new(event: ManifestEvent) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event,
            digest: None,
            children: Vec::new(),
        }
    }

    pub fn add_child(&mut self, child: ManifestChild) {
        self.children.push(child);
    }

    /// Serialize to canonical JSON (sorted keys, excluding digest object)
    pub fn to_canonical_json(&self) -> Result<String> {
        // TODO: Implement proper canonical JSON serialization with sorted keys
        // For now, manually construct in alphabetical order per spec
        let children_json: Vec<String> = self
            .children
            .iter()
            .map(|c| {
                let revoked_at = c
                    .revoked_at
                    .map(|t| format!(r#","revoked_at":"{}""#, t.to_rfc3339()))
                    .unwrap_or_default();
                let ciphertext = c
                    .ciphertext_md5
                    .as_ref()
                    .map(|md5| format!(r#","ciphertext_md5":"{}""#, md5))
                    .unwrap_or_default();
                let scope = c
                    .scope
                    .as_ref()
                    .map(|s| {
                        let paths = s
                            .paths
                            .iter()
                            .map(|p| format!(r#""{}""#, p))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!(
                            r#","scope":{{"env":"{}","paths":[{}]}}"#,
                            s.env, paths
                        )
                    })
                    .unwrap_or_default();

                format!(
                    r#"{{"fingerprint":"{}","issued_at":"{}","role":"{}","status":"{}"{}{}{}}}"#,
                    c.fingerprint, c.issued_at.to_rfc3339(), c.role, c.status, ciphertext, scope, revoked_at
                )
            })
            .collect();

        let event_json = format!(
            r#"{{"event_type":"{}","initiated_at":"{}","initiated_by":"{}","parent_fingerprint":"{}","reason":"{}"}}"#,
            self.event.event_type.as_str(),
            self.event.initiated_at.to_rfc3339(),
            self.event.initiated_by,
            self.event.parent_fingerprint,
            self.event.reason
        );

        Ok(format!(
            r#"{{"children":[{}],"event":{},"schema_version":"{}"}}"#,
            children_json.join(","),
            event_json,
            self.schema_version
        ))
    }

    /// Compute and set digest for this manifest
    pub fn compute_digest(&mut self) -> Result<()> {
        let canonical = self.to_canonical_json()?;
        self.digest = Some(ManifestDigest::compute(&canonical));
        Ok(())
    }

    /// Serialize to complete JSON including digest
    pub fn to_json_with_digest(&self) -> Result<String> {
        let canonical = self.to_canonical_json()?;
        let digest = self
            .digest
            .as_ref()
            .ok_or_else(|| IgniteError::InvalidOperation {
                operation: "serialize_manifest".to_string(),
                reason: "Digest not computed - call compute_digest() first".to_string(),
            })?;

        let digest_json = format!(
            r#"{{"algorithm":"{}","manifest_body":"{}","value":"{}"}}"#,
            digest.algorithm, digest.manifest_body, digest.value
        );

        // Insert digest into canonical JSON
        // Find the position after "children":[...] and before "event":
        let insert_pos = canonical
            .find(",\"event\":")
            .ok_or_else(|| IgniteError::InvalidOperation {
                operation: "insert_digest".to_string(),
                reason: "Could not find event field in JSON".to_string(),
            })?;

        let mut result = String::with_capacity(canonical.len() + digest_json.len() + 20);
        result.push_str(&canonical[..insert_pos]);
        result.push_str(",\"digest\":");
        result.push_str(&digest_json);
        result.push_str(&canonical[insert_pos..]);

        Ok(result)
    }

    /// Verify digest matches canonical payload
    pub fn verify_digest(&self) -> Result<()> {
        let canonical = self.to_canonical_json()?;
        let computed = ManifestDigest::compute(&canonical);

        let stored = self.digest.as_ref().ok_or_else(|| IgniteError::InvalidOperation {
            operation: "verify_manifest_digest".to_string(),
            reason: "No digest present in manifest".to_string(),
        })?;

        if computed.value != stored.value {
            return Err(IgniteError::CryptoError {
                operation: "verify_manifest_digest".to_string(),
                reason: "Digest mismatch - manifest may have been tampered with".to_string(),
            });
        }

        Ok(())
    }

    /// Generate filename for this manifest (parent_fp/timestamp_event.json)
    pub fn filename(&self) -> String {
        let timestamp = self
            .event
            .initiated_at
            .format("%Y-%m-%dT%H-%M-%SZ")
            .to_string();
        format!(
            "{}/{}_{}.json",
            self.event.parent_fingerprint.short(),
            timestamp,
            self.event.event_type.as_str()
        )
    }
}

// TODO: Implement manifest persistence to vault (data/manifests/)
// TODO: Implement manifest loading and validation from disk
// TODO: Add CLI command `ignite manifest --verify <file>` handler
// TODO: Integrate manifest generation with rotation/revocation operations

#[cfg(test)]
mod tests {
    use super::*;
    use hub::time_ext::chrono::TimeZone;

    fn create_test_fingerprint(suffix: &str) -> KeyFingerprint {
        KeyFingerprint::from_string(&format!("SHA256:test{}", suffix)).unwrap()
    }

    fn create_test_event() -> ManifestEvent {
        ManifestEvent::new(
            ManifestEventType::Rotation,
            create_test_fingerprint("parent"),
            "Test rotation event",
        )
    }

    #[test]
    fn test_manifest_event_creation() {
        let parent_fp = create_test_fingerprint("parent");
        let event = ManifestEvent::new(
            ManifestEventType::Revocation,
            parent_fp.clone(),
            "Security breach",
        );

        assert_eq!(event.event_type, ManifestEventType::Revocation);
        assert_eq!(event.parent_fingerprint, parent_fp);
        assert_eq!(event.reason, "Security breach");
        assert_eq!(event.initiated_by, "ignite-cli");
        assert!(event.initiated_at <= Utc::now());
    }

    #[test]
    fn test_manifest_event_type_string() {
        assert_eq!(ManifestEventType::Rotation.as_str(), "rotation");
        assert_eq!(ManifestEventType::Revocation.as_str(), "revocation");
    }

    #[test]
    fn test_manifest_child_creation() {
        let child_fp = create_test_fingerprint("child");
        let issued_at = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();

        let child = ManifestChild::new(
            child_fp.clone(),
            KeyType::Ignition,
            "active",
            issued_at,
        );

        assert_eq!(child.fingerprint, child_fp);
        assert_eq!(child.role, KeyType::Ignition);
        assert_eq!(child.status, "active");
        assert_eq!(child.issued_at, issued_at);
        assert!(child.revoked_at.is_none());
        assert!(child.scope.is_none());
        assert!(child.ciphertext_md5.is_none());
    }

    #[test]
    fn test_manifest_child_with_modifiers() {
        let child_fp = create_test_fingerprint("child");
        let issued_at = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
        let revoked_at = Utc.with_ymd_and_hms(2024, 1, 2, 12, 0, 0).unwrap();
        let scope = ManifestScope::new(vec!["path1".to_string(), "path2".to_string()], "production");

        let child = ManifestChild::new(child_fp, KeyType::Ignition, "revoked", issued_at)
            .with_revocation(revoked_at)
            .with_scope(scope)
            .with_ciphertext_md5("abc123".to_string());

        assert_eq!(child.revoked_at, Some(revoked_at));
        assert!(child.scope.is_some());
        assert_eq!(child.scope.as_ref().unwrap().env, "production");
        assert_eq!(child.ciphertext_md5, Some("abc123".to_string()));
    }

    #[test]
    fn test_affected_key_manifest_creation() {
        let event = create_test_event();
        let manifest = AffectedKeyManifest::new(event);

        assert_eq!(manifest.schema_version, "1.0");
        assert!(manifest.children.is_empty());
        assert!(manifest.digest.is_none());
    }

    #[test]
    fn test_manifest_add_children() {
        let event = create_test_event();
        let mut manifest = AffectedKeyManifest::new(event);

        let child1 = ManifestChild::new(
            create_test_fingerprint("child1"),
            KeyType::Ignition,
            "active",
            Utc::now(),
        );

        let child2 = ManifestChild::new(
            create_test_fingerprint("child2"),
            KeyType::Distro,
            "revoked",
            Utc::now(),
        );

        manifest.add_child(child1);
        manifest.add_child(child2);

        assert_eq!(manifest.children.len(), 2);
        assert_eq!(manifest.children[0].role, KeyType::Ignition);
        assert_eq!(manifest.children[1].role, KeyType::Distro);
    }

    #[test]
    fn test_manifest_canonical_json() {
        let event = create_test_event();
        let mut manifest = AffectedKeyManifest::new(event);

        let child = ManifestChild::new(
            create_test_fingerprint("child"),
            KeyType::Ignition,
            "active",
            Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap(),
        );

        manifest.add_child(child);

        let json = manifest.to_canonical_json().unwrap();

        // Verify JSON structure (alphabetically sorted keys)
        assert!(json.contains("\"children\":["));
        assert!(json.contains("\"event\":{"));
        assert!(json.contains("\"schema_version\":\"1.0\""));
        assert!(json.contains("\"fingerprint\":"));
        assert!(json.contains("\"role\":\"ignition\""));
        assert!(json.contains("\"status\":\"active\""));

        // Verify alphabetical order
        let children_pos = json.find("\"children\"").unwrap();
        let event_pos = json.find("\"event\"").unwrap();
        let schema_pos = json.find("\"schema_version\"").unwrap();
        assert!(children_pos < event_pos);
        assert!(event_pos < schema_pos);
    }

    #[test]
    fn test_manifest_digest_computation() {
        let event = create_test_event();
        let mut manifest = AffectedKeyManifest::new(event);

        let child = ManifestChild::new(
            create_test_fingerprint("child"),
            KeyType::Ignition,
            "active",
            Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap(),
        );

        manifest.add_child(child);

        // Compute digest
        manifest.compute_digest().unwrap();

        assert!(manifest.digest.is_some());
        let digest = manifest.digest.as_ref().unwrap();
        assert_eq!(digest.algorithm, "SHA256");
        assert_eq!(digest.manifest_body, "canonical");
        assert!(!digest.value.is_empty());
    }

    #[test]
    fn test_manifest_digest_verification() {
        let event = create_test_event();
        let mut manifest = AffectedKeyManifest::new(event);

        let child = ManifestChild::new(
            create_test_fingerprint("child"),
            KeyType::Ignition,
            "active",
            Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap(),
        );

        manifest.add_child(child);
        manifest.compute_digest().unwrap();

        // Verification should pass
        assert!(manifest.verify_digest().is_ok());

        // Tamper with the manifest
        manifest.children[0].status = "tampered".to_string();

        // Verification should now fail
        assert!(manifest.verify_digest().is_err());
    }

    #[test]
    fn test_manifest_json_with_digest() {
        let event = create_test_event();
        let mut manifest = AffectedKeyManifest::new(event);

        let child = ManifestChild::new(
            create_test_fingerprint("child"),
            KeyType::Ignition,
            "active",
            Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap(),
        );

        manifest.add_child(child);
        manifest.compute_digest().unwrap();

        let json = manifest.to_json_with_digest().unwrap();

        // Verify digest is included
        assert!(json.contains("\"digest\":{"));
        assert!(json.contains("\"algorithm\":\"SHA256\""));
        assert!(json.contains("\"manifest_body\":\"canonical\""));
        assert!(json.contains("\"value\":"));

        // Verify digest comes before event in the JSON
        let digest_pos = json.find("\"digest\"").unwrap();
        let event_pos = json.find("\"event\"").unwrap();
        assert!(digest_pos < event_pos);
    }

    #[test]
    fn test_manifest_filename_generation() {
        let parent_fp = create_test_fingerprint("parent");
        let mut event = ManifestEvent::new(
            ManifestEventType::Rotation,
            parent_fp,
            "Test rotation",
        );

        // Set a specific timestamp for predictable filename
        event.initiated_at = Utc.with_ymd_and_hms(2024, 1, 15, 14, 30, 45).unwrap();

        let manifest = AffectedKeyManifest::new(event);
        let filename = manifest.filename();

        assert_eq!(filename, "testpare/2024-01-15T14-30-45Z_rotation.json");
    }

    #[test]
    fn test_manifest_scope() {
        let scope = ManifestScope::new(
            vec!["src/main.rs".to_string(), "Cargo.toml".to_string()],
            "development",
        );

        assert_eq!(scope.paths.len(), 2);
        assert_eq!(scope.paths[0], "src/main.rs");
        assert_eq!(scope.env, "development");
    }
}
