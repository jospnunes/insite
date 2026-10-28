//! Where insite keeps data from `insite update` (cache) and the user's own
//! signatures (configuration), per platform.

use std::path::PathBuf;

/// `$XDG_CONFIG_HOME/insite` (default `~/.config/insite`) on Linux,
/// `~/Library/Application Support/insite` on macOS, `%APPDATA%\insite` on Windows.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env_dir("APPDATA").map(|d| d.join("insite"))
    } else if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/Application Support/insite"))
    } else {
        env_dir("XDG_CONFIG_HOME")
            .or_else(|| home().map(|h| h.join(".config")))
            .map(|d| d.join("insite"))
    }
}

/// `$XDG_CACHE_HOME/insite` (default `~/.cache/insite`) on Linux,
/// `~/Library/Caches/insite` on macOS, `%LOCALAPPDATA%\insite\cache` on Windows.
pub fn cache_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env_dir("LOCALAPPDATA").map(|d| d.join("insite").join("cache"))
    } else if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/Caches/insite"))
    } else {
        env_dir("XDG_CACHE_HOME")
            .or_else(|| home().map(|h| h.join(".cache")))
            .map(|d| d.join("insite"))
    }
}

/// An absolute directory from an environment variable; relative ones are
/// ignored, as the XDG specification says.
fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute())
}

fn home() -> Option<PathBuf> {
    env_dir(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
}
