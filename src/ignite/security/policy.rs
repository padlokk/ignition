//! Modular security policy engine for Ignite.
//!
//! This module provides a composable policy engine that can host multiple
//! validation policies. Policies participate in three phases:
//!   * `apply_key_defaults` – mutate key metadata before persistence
//!   * `validate_key` – enforce key-level invariants (expiration, hierarchy, etc.)
//!   * `validate_passphrase` – enforce passphrase rules for ignition-wrapped keys
//!
//! The engine ships with two default policies:
//!   * `ExpirationPolicy` – enforces default expiry windows and rejects expired keys
//!   * `PassphraseStrengthPolicy` – enforces length/diversity/banned-pattern rules
//!
//! Additional policies can be registered at runtime via `PolicyEngine::register_policy`.

use std::collections::HashMap;

use hub::time_ext::chrono::{DateTime, Duration, Utc};

use crate::ignite::authority::{AuthorityKey, KeyMetadata, KeyType};
use crate::ignite::error::{IgniteError, Result};

/// Pluggable policy contract.
pub trait Policy: Send + Sync {
    fn name(&self) -> &'static str;

    fn apply_key_defaults(&self, _key: &mut AuthorityKey) -> Result<()> {
        Ok(())
    }

    fn validate_key(&self, _key: &AuthorityKey) -> Result<()> {
        Ok(())
    }

    fn validate_passphrase(&self, _key_type: KeyType, _passphrase: &str) -> Result<()> {
        Ok(())
    }
}

/// Central policy engine.
#[derive(Default)]
pub struct PolicyEngine {
    policies: Vec<Box<dyn Policy>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Install the default policy bundle (expiration + passphrase strength).
    pub fn with_defaults() -> Self {
        let mut engine = Self::new();
        engine.register_policy(ExpirationPolicy::default());
        engine.register_policy(PassphraseStrengthPolicy::default());
        engine
    }

    pub fn register_policy<P>(&mut self, policy: P)
    where
        P: Policy + 'static,
    {
        self.policies.push(Box::new(policy));
    }

    pub fn apply_key_defaults(&self, key: &mut AuthorityKey) -> Result<()> {
        for policy in &self.policies {
            policy.apply_key_defaults(key)?;
        }
        Ok(())
    }

    pub fn validate_key(&self, key: &AuthorityKey) -> Result<()> {
        for policy in &self.policies {
            policy.validate_key(key)?;
        }
        Ok(())
    }

    pub fn validate_passphrase(&self, key_type: KeyType, passphrase: &str) -> Result<()> {
        for policy in &self.policies {
            policy.validate_passphrase(key_type, passphrase)?;
        }
        Ok(())
    }
}

/// Default expiration policy per key tier.
#[derive(Debug, Clone)]
pub struct ExpirationPolicy {
    defaults: HashMap<KeyType, Duration>,
    warning_fraction: f32,
}

impl ExpirationPolicy {
    pub fn new() -> Self {
        let mut defaults = HashMap::new();
        defaults.insert(KeyType::Ignition, Duration::days(30));
        defaults.insert(KeyType::Distro, Duration::days(7));

        Self {
            defaults,
            warning_fraction: 0.1,
        }
    }

    fn duration_for(&self, key_type: KeyType) -> Option<Duration> {
        self.defaults.get(&key_type).copied()
    }

    fn compute_expiration(&self, key: &AuthorityKey) -> Option<DateTime<Utc>> {
        self.duration_for(key.key_type())
            .map(|delta| key.metadata().creation_time + delta)
    }

    fn is_warning(&self, metadata: &KeyMetadata) -> bool {
        match (metadata.expiration(), self.warning_fraction) {
            (Some(expiration), fraction) if fraction > 0.0 => {
                let total = expiration - metadata.creation_time;
                let total_secs = total.num_seconds();
                if total_secs <= 0 {
                    return true;
                }
                let warning_secs = ((total_secs as f64) * (fraction.min(1.0) as f64)).max(1.0);
                let warning_window = Duration::seconds(warning_secs as i64);
                Utc::now() >= (expiration - warning_window)
            }
            _ => false,
        }
    }
}

impl Default for ExpirationPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for ExpirationPolicy {
    fn name(&self) -> &'static str {
        "expiration"
    }

    fn apply_key_defaults(&self, key: &mut AuthorityKey) -> Result<()> {
        if key.metadata().expiration().is_none() {
            if let Some(expiration) = self.compute_expiration(key) {
                key.metadata_mut().set_expiration(Some(expiration));
            }
        }
        Ok(())
    }

    fn validate_key(&self, key: &AuthorityKey) -> Result<()> {
        if let Some(expiration) = key.metadata().expiration() {
            if Utc::now() > expiration {
                return Err(IgniteError::InvalidOperation {
                    operation: "policy_expiration".to_string(),
                    reason: format!("Key {} has expired", key.fingerprint()),
                });
            }

            if self.is_warning(key.metadata()) {
                // TODO: Route warning to logging once audit hooks land.
            }
        }

        Ok(())
    }
}

/// Passphrase strength enforcement policy.
#[derive(Debug, Clone, Default)]
pub struct PassphraseStrengthPolicy;

impl PassphraseStrengthPolicy {
    fn validate(&self, passphrase: &str) -> Result<()> {
        if passphrase.len() < 12 {
            return Err(IgniteError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: "Passphrase must be at least 12 characters long".to_string(),
            });
        }

        if passphrase.len() > 256 {
            return Err(IgniteError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: "Passphrase must be less than 256 characters".to_string(),
            });
        }

        let has_upper = passphrase.chars().any(|c| c.is_uppercase());
        let has_lower = passphrase.chars().any(|c| c.is_lowercase());
        let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
        let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

        let diversity = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .filter(|&&b| b)
            .count();

        if diversity < 3 {
            return Err(IgniteError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: "Passphrase must contain at least three of: uppercase, lowercase, digits, special characters".to_string(),
            });
        }

        if is_common_password(passphrase) {
            return Err(IgniteError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: "Common password detected. Please choose a unique passphrase".to_string(),
            });
        }

        let injection_patterns = ["$(", "`", ";", "&", "|", "\n", "\r", "\0"];
        if injection_patterns
            .iter()
            .any(|pat| passphrase.contains(pat))
        {
            return Err(IgniteError::InvalidOperation {
                operation: "validate_passphrase".to_string(),
                reason: "Passphrase contains potentially dangerous shell characters".to_string(),
            });
        }

        Ok(())
    }
}

impl Policy for PassphraseStrengthPolicy {
    fn name(&self) -> &'static str {
        "passphrase_strength"
    }

    fn validate_passphrase(&self, key_type: KeyType, passphrase: &str) -> Result<()> {
        if key_type.is_ignition_key() {
            self.validate(passphrase)
        } else {
            Ok(())
        }
    }
}

fn is_common_password(passphrase: &str) -> bool {
    let common_passwords = [
        "password",
        "123456",
        "password123",
        "admin",
        "qwerty",
        "letmein",
        "welcome",
        "monkey",
        "1234567890",
        "abc123",
    ];

    let lower = passphrase.to_lowercase();
    common_passwords
        .iter()
        .any(|candidate| lower.contains(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignite::authority::{AuthorityKey, KeyFormat, KeyMaterial};
    use ed25519_dalek::{SecretKey, SigningKey};
    use hub::random_ext::rand::{rng, Rng};

    fn sample_key(key_type: KeyType) -> AuthorityKey {
        let mut random = rng();
        let secret_bytes: [u8; 32] = random.random();
        let secret_key = SecretKey::from(secret_bytes);
        let signing_key = SigningKey::from(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_key = Some(signing_key.to_bytes().to_vec());
        let material = KeyMaterial::new(public_key, private_key, KeyFormat::Ed25519);

        AuthorityKey::new(material, key_type, None, None).unwrap()
    }

    #[test]
    fn expiration_policy_sets_defaults() {
        let policy = ExpirationPolicy::default();
        let mut distro_key = sample_key(KeyType::Distro);
        policy.apply_key_defaults(&mut distro_key).unwrap();
        assert!(distro_key.metadata().expiration().is_some());

        let master_key = sample_key(KeyType::Master);
        assert!(master_key.metadata().expiration().is_none());
    }

    #[test]
    fn expiration_policy_rejects_expired_keys() {
        let policy = ExpirationPolicy::default();
        let mut ignition_key = sample_key(KeyType::Ignition);
        ignition_key
            .metadata_mut()
            .set_expiration(Some(Utc::now() - Duration::hours(1)));

        assert!(policy.validate_key(&ignition_key).is_err());
    }

    #[test]
    fn passphrase_policy_enforces_rules() {
        let engine = PolicyEngine::with_defaults();
        assert!(engine
            .validate_passphrase(KeyType::Ignition, "MySecure123!Pass")
            .is_ok());
        assert!(engine
            .validate_passphrase(KeyType::Ignition, "short")
            .is_err());
        assert!(engine
            .validate_passphrase(KeyType::Ignition, "password123Secure")
            .is_err());
    }

    #[test]
    fn engine_allows_policy_registration() {
        struct NoOpPolicy;
        impl Policy for NoOpPolicy {
            fn name(&self) -> &'static str {
                "noop"
            }
        }

        let mut engine = PolicyEngine::new();
        engine.register_policy(NoOpPolicy);

        let key = sample_key(KeyType::Master);
        assert!(engine.validate_key(&key).is_ok());
    }
}
