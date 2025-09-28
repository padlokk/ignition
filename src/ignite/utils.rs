//! General utilities shared across ignite modules.

use std::env;
use std::path::PathBuf;

fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./"))
}

/// Resolve the writable data root for ignite, following XDG+ precedence.
pub fn data_root() -> PathBuf {
    if let Ok(dir) = env::var("IGNITE_DATA_ROOT") {
        return PathBuf::from(dir);
    }

    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("padlokk").join("ignite");
    }

    home_dir().join(".local/share/padlokk/ignite")
}

/// Resolve the config root for ignite, following XDG+ precedence.
pub fn config_root() -> PathBuf {
    if let Ok(dir) = env::var("IGNITE_CONFIG_ROOT") {
        return PathBuf::from(dir);
    }

    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("padlokk").join("ignite");
    }

    home_dir().join(".config/padlokk/ignite")
}

/// Vault subdirectory paths for organized storage

/// Path to keys directory within vault
pub fn keys_dir() -> PathBuf {
    data_root().join("keys")
}

/// Path to proofs directory within vault
pub fn proofs_dir() -> PathBuf {
    data_root().join("proofs")
}

/// Path to manifests directory within vault
pub fn manifests_dir() -> PathBuf {
    data_root().join("manifests")
}

/// Path to metadata directory within vault
pub fn metadata_dir() -> PathBuf {
    data_root().join("metadata")
}

/// Ensure all vault directories exist
pub fn ensure_vault_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(keys_dir())?;
    std::fs::create_dir_all(proofs_dir())?;
    std::fs::create_dir_all(manifests_dir())?;
    std::fs::create_dir_all(metadata_dir())?;
    Ok(())
}
