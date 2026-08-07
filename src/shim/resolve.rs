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

/// Find the real `tool` on PATH, skipping this process's executable and any
/// pkg-guard multicall shims (symlinks/copies named after package managers).
///
/// Prefer a **dedicated shim directory** early on PATH (default
/// `~/.local/share/pkg-guard/shims`) and leave real tools in their normal
/// install locations (`~/.local/bin`, nvm, cargo, …). Do not relocate reals.
///
/// Optional `PKG_GUARD_REAL_<TOOL>` forces an absolute path when PATH lookup
/// is insufficient.
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
        if is_pkg_guard_wrapper(&candidate, self_canon.as_ref()) {
            continue;
        }
        return Ok(candidate);
    }

    bail!(
        "could not find real '{tool}' on PATH (skipped pkg-guard shims). \
         Put real tools after the shim dir on PATH, or set {}=/absolute/path/to/{tool}",
        env_key_for(tool)
    )
}

/// True if `candidate` is this pkg-guard binary or a multicall shim pointing at it.
fn is_pkg_guard_wrapper(candidate: &Path, self_canon: Option<&PathBuf>) -> bool {
    // Same inode/path as the running binary (after following symlinks).
    if let (Ok(c), Some(s)) = (candidate.canonicalize(), self_canon) {
        if c == *s {
            return true;
        }
        // Another install of pkg-guard used as a shim target.
        if c.file_name().and_then(|n| n.to_str()) == Some("pkg-guard") {
            return true;
        }
    }

    // Symlink whose link text ends in pkg-guard (even if target is temporarily missing).
    if let Ok(meta) = candidate.symlink_metadata() {
        if meta.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(candidate) {
                if target.file_name().and_then(|n| n.to_str()) == Some("pkg-guard") {
                    return true;
                }
            }
        }
    }

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
        assert_eq!(env_key_for("uvx"), "PKG_GUARD_REAL_UVX");
    }

    #[test]
    #[serial_test::serial]
    fn test_skips_shim_symlink_finds_later_real() {
        let root = std::env::temp_dir().join(format!(
            "pkg-guard-resolve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let shim_dir = root.join("shims");
        let real_dir = root.join("real");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        // Fake "pkg-guard" binary target for the shim symlink.
        let fake_pg = root.join("pkg-guard");
        std::fs::write(&fake_pg, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_pg).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_pg, perms).unwrap();
            std::os::unix::fs::symlink(&fake_pg, shim_dir.join("uvx")).unwrap();
        }

        // Real uvx later on PATH.
        let real_uvx = real_dir.join("uvx");
        std::fs::write(&real_uvx, b"#!/bin/sh\necho real\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&real_uvx).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&real_uvx, perms).unwrap();
        }

        let old_path = env::var_os("PATH");
        let old_real = env::var_os("PKG_GUARD_REAL_UVX");
        env::remove_var("PKG_GUARD_REAL_UVX");
        let new_path = env::join_paths([shim_dir.as_path(), real_dir.as_path()]).unwrap();
        env::set_var("PATH", &new_path);

        let found = resolve_real_binary("uvx").expect("should find real uvx");
        assert_eq!(
            found.canonicalize().unwrap(),
            real_uvx.canonicalize().unwrap()
        );

        match old_path {
            Some(p) => env::set_var("PATH", p),
            None => env::remove_var("PATH"),
        }
        match old_real {
            Some(p) => env::set_var("PKG_GUARD_REAL_UVX", p),
            None => env::remove_var("PKG_GUARD_REAL_UVX"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
