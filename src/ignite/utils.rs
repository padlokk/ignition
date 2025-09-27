//! General utilities shared across ignite modules.

use std::env;
use std::path::PathBuf;

fn home_dir() -> PathBuf {
    env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./"))
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
