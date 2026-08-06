//! User- and project-maintained custom blocklists.
//!
//! These exist so operators can block brand-new threats **immediately**, without
//! waiting for internet feeds or a pkg-guard release. Custom entries always win
//! over (and are checked before) the embedded seed list.
//!
//! ## Load order (all files that exist are **merged**)
//!
//! 1. `PKG_GUARD_BLOCKLIST` — path to a JSON file (env)
//! 2. `$XDG_CONFIG_HOME/pkg-guard/blocklist.json` or `~/.config/pkg-guard/blocklist.json`
//! 3. `./.pkg-guard/blocklist.json` (project-local, relative to process CWD)
//!
//! ## File format
//!
//! ```json
//! {
//!   "version": 1,
//!   "python": ["evil-package", "typo-name"],
//!   "npm": ["evil-npm"],
//!   "java": ["com.evil:artifact"]
//! }
//! ```
//!
//! Names are matched case-insensitively. Unknown fields are ignored.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use serde::Deserialize;
use tracing::{debug, warn};

use super::Ecosystem;

/// JSON shape for custom blocklist files.
#[derive(Debug, Default, Deserialize)]
struct BlocklistFile {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    python: Vec<String>,
    #[serde(default)]
    npm: Vec<String>,
    #[serde(default)]
    java: Vec<String>,
}

/// Merged runtime view of all custom lists.
#[derive(Debug, Default, Clone)]
pub struct CustomBlocklist {
    python: HashSet<String>,
    npm: HashSet<String>,
    java: HashSet<String>,
    /// Paths that were successfully loaded (for diagnostics).
    pub loaded_paths: Vec<PathBuf>,
    /// Paths that existed but failed to parse.
    pub errors: Vec<String>,
    /// Wall-clock of last successful load (for mtime-based refresh).
    loaded_at: Option<SystemTime>,
}

impl CustomBlocklist {
    fn contains(&self, ecosystem: Ecosystem, package_name: &str) -> bool {
        let name = package_name.to_lowercase();
        match ecosystem {
            Ecosystem::Python => self.python.contains(&name),
            Ecosystem::Npm => self.npm.contains(&name),
            Ecosystem::Java => self.java.contains(&name),
        }
    }

    fn merge_file(&mut self, path: &Path, file: BlocklistFile) {
        for name in file.python {
            self.python.insert(name.to_lowercase());
        }
        for name in file.npm {
            self.npm.insert(name.to_lowercase());
        }
        for name in file.java {
            self.java.insert(name.to_lowercase());
        }
        self.loaded_paths.push(path.to_path_buf());
        if let Some(v) = file.version {
            debug!("Loaded custom blocklist {} (version {v})", path.display());
        } else {
            debug!("Loaded custom blocklist {}", path.display());
        }
    }

    /// Total custom entries across ecosystems.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.python.len() + self.npm.len() + self.java.len()
    }
}

static CUSTOM: OnceLock<Mutex<CustomBlocklist>> = OnceLock::new();

fn state() -> &'static Mutex<CustomBlocklist> {
    CUSTOM.get_or_init(|| Mutex::new(load_all()))
}

/// Paths consulted for custom blocklists (whether or not they exist).
#[must_use]
pub fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_path) = std::env::var("PKG_GUARD_BLOCKLIST") {
        let p = PathBuf::from(env_path.trim());
        if !p.as_os_str().is_empty() {
            paths.push(p);
        }
    }

    if let Some(cfg) = user_config_blocklist_path() {
        paths.push(cfg);
    }

    paths.push(PathBuf::from(".pkg-guard/blocklist.json"));
    paths
}

fn user_config_blocklist_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("pkg-guard/blocklist.json"));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/pkg-guard/blocklist.json"))
}

fn load_all() -> CustomBlocklist {
    let mut merged = CustomBlocklist::default();
    for path in candidate_paths() {
        load_one(&path, &mut merged);
    }
    merged.loaded_at = Some(SystemTime::now());
    merged
}

/// True if any candidate file is newer than the last load (or appeared since).
fn disk_is_newer_than(loaded_at: SystemTime) -> bool {
    for path in candidate_paths() {
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if modified > loaded_at {
                    return true;
                }
            }
        }
    }
    false
}

/// Reload from disk when a custom blocklist file changed (MCP-friendly).
fn refresh_if_stale() {
    let Ok(guard) = state().lock() else {
        return;
    };
    let needs = match guard.loaded_at {
        Some(t) => disk_is_newer_than(t),
        None => true,
    };
    drop(guard);
    if needs {
        debug!("Custom blocklist changed on disk; reloading");
        reload();
    }
}

fn load_one(path: &Path, into: &mut CustomBlocklist) {
    if !path.is_file() {
        return;
    }
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<BlocklistFile>(&text) {
            Ok(file) => into.merge_file(path, file),
            Err(e) => {
                let msg = format!("Failed to parse custom blocklist {}: {e}", path.display());
                warn!("{msg}");
                into.errors.push(msg);
            }
        },
        Err(e) => {
            let msg = format!("Failed to read custom blocklist {}: {e}", path.display());
            warn!("{msg}");
            into.errors.push(msg);
        }
    }
}

/// Reload custom blocklists from disk (e.g. after the user edits a file).
pub fn reload() {
    let fresh = load_all();
    if let Ok(mut guard) = state().lock() {
        *guard = fresh;
    }
}

/// Snapshot of the current merged custom blocklist (for CLI diagnostics).
#[must_use]
pub fn snapshot() -> CustomBlocklist {
    state().lock().map(|g| g.clone()).unwrap_or_default()
}

/// True if the package is on any **custom** (user/project/env) blocklist.
#[must_use]
pub fn is_custom_blocklisted(ecosystem: Ecosystem, package_name: &str) -> bool {
    refresh_if_stale();
    state()
        .lock()
        .map(|g| g.contains(ecosystem, package_name))
        .unwrap_or(false)
}

/// Write an example blocklist file to `path` (parent dirs created).
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn write_example(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let example = r#"{
  "version": 1,
  "python": [
    "example-malicious-package"
  ],
  "npm": [],
  "java": []
}
"#;
    fs::write(path, example)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_merge_file_normalizes_case() {
        let mut c = CustomBlocklist::default();
        c.merge_file(
            Path::new("/tmp/test-blocklist.json"),
            BlocklistFile {
                version: Some(1),
                python: vec!["Evil-Pkg".to_string()],
                npm: vec![],
                java: vec![],
            },
        );
        assert!(c.contains(Ecosystem::Python, "evil-pkg"));
        assert!(c.contains(Ecosystem::Python, "EVIL-PKG"));
        assert!(!c.contains(Ecosystem::Npm, "evil-pkg"));
    }

    #[test]
    fn test_load_one_from_disk() {
        let dir = std::env::temp_dir().join(format!("pkg-guard-bl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("blocklist.json");
        let mut f = fs::File::create(&path).expect("create");
        write!(
            f,
            r#"{{"python":["brand-new-threat"],"npm":["npm-zero-day"],"java":[]}}"#
        )
        .expect("write");

        let mut c = CustomBlocklist::default();
        load_one(&path, &mut c);
        assert!(c.contains(Ecosystem::Python, "brand-new-threat"));
        assert!(c.contains(Ecosystem::Npm, "npm-zero-day"));
        assert_eq!(c.loaded_paths.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_example() {
        let dir = std::env::temp_dir().join(format!("pkg-guard-ex-{}", std::process::id()));
        let path = dir.join("blocklist.json");
        write_example(&path).expect("write example");
        assert!(path.is_file());
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("python"));
        let _ = fs::remove_dir_all(&dir);
    }
}
