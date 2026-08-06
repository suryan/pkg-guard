//! Locate the real package-manager binary without recursing into ourselves.

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Environment override for a tool, e.g. `pip` → `PKG_GUARD_REAL_PIP`.
#[must_use]
pub fn env_key_for(tool: &str) -> String {
    let upper = tool.to_ascii_uppercase().replace('-', "_");
    format!("PKG_GUARD_REAL_{upper}")
}

/// Find the real `tool` on PATH, skipping this process's executable.
///
/// # Errors
/// Returns an error if no suitable binary is found.
pub fn resolve_real_binary(tool: &str) -> Result<PathBuf> {
    if let Ok(p) = env::var(env_key_for(tool)) {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "{} points to missing file: {}",
            env_key_for(tool),
            path.display()
        );
    }

    let self_canon = env::current_exe().ok().and_then(|p| p.canonicalize().ok());

    let path_var = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(tool);
        if !is_executable(&candidate) {
            continue;
        }
        if is_self(&candidate, self_canon.as_ref()) {
            continue;
        }
        return Ok(candidate);
    }

    bail!(
        "could not find real '{tool}' on PATH (skipped pkg-guard shims). \
         Set {}=/absolute/path/to/{tool}",
        env_key_for(tool)
    )
}

fn is_self(candidate: &Path, self_canon: Option<&PathBuf>) -> bool {
    let Some(self_path) = self_canon else {
        return false;
    };
    if let Ok(c) = candidate.canonicalize() {
        if c == *self_path {
            return true;
        }
    }
    // Also compare non-canonical if symlink-heavy
    false
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && path
            .metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_key() {
        assert_eq!(env_key_for("pip"), "PKG_GUARD_REAL_PIP");
        assert_eq!(env_key_for("pip3"), "PKG_GUARD_REAL_PIP3");
    }
}
