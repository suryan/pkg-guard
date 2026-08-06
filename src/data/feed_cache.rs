//! Runtime feed cache produced by `pkg-guard update-db`.
//!
//! Default path: `$XDG_CACHE_HOME/pkg-guard/blocklist-cache.json`
//! or `~/.cache/pkg-guard/blocklist-cache.json`.
//!
//! Override with `PKG_GUARD_CACHE_DIR`.

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use tracing::{debug, warn};

use super::blocklist_format::{parse_document, BlocklistDocument, EcosystemSets};
use super::Ecosystem;

/// Warn when the feed cache is older than this many days (or missing).
pub const MAX_CACHE_AGE_DAYS: u64 = 7;

#[derive(Default)]
struct CacheState {
    sets: EcosystemSets,
    updated_at: Option<String>,
    sources: Vec<String>,
    errors: Vec<String>,
}

static STATE: OnceLock<Mutex<CacheState>> = OnceLock::new();

fn state() -> &'static Mutex<CacheState> {
    STATE.get_or_init(|| Mutex::new(load_cache()))
}

/// Directory for feed cache files.
#[must_use]
pub fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PKG_GUARD_CACHE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("pkg-guard");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache/pkg-guard")
}

/// Path to the merged feed cache JSON.
#[must_use]
pub fn cache_path() -> PathBuf {
    cache_dir().join("blocklist-cache.json")
}

fn load_cache() -> CacheState {
    let path = cache_path();
    let mut state = CacheState::default();

    if !path.is_file() {
        debug!("No feed cache at {}", path.display());
        return state;
    }

    match fs::read_to_string(&path) {
        Ok(text) => match parse_document(&text) {
            Ok(doc) => {
                state.updated_at.clone_from(&doc.updated_at);
                state.sources.clone_from(&doc.sources);
                state.sets = doc.to_sets();
                debug!(
                    "Loaded feed cache {} ({} entries)",
                    path.display(),
                    state.sets.total()
                );
            }
            Err(e) => {
                let msg = format!("Failed to parse feed cache {}: {e}", path.display());
                warn!("{msg}");
                state.errors.push(msg);
            }
        },
        Err(e) => {
            let msg = format!("Failed to read feed cache {}: {e}", path.display());
            warn!("{msg}");
            state.errors.push(msg);
        }
    }
    state
}

/// Reload feed cache from disk.
pub fn reload() {
    let fresh = load_cache();
    if let Ok(mut guard) = state().lock() {
        *guard = fresh;
    }
}

/// Write a document to the cache path and reload in-memory state.
///
/// # Errors
/// Returns an error if the directory or file cannot be written.
pub fn write_cache(doc: &BlocklistDocument) -> anyhow::Result<PathBuf> {
    let dir = cache_dir();
    fs::create_dir_all(&dir)?;
    let path = cache_path();
    let text = serde_json::to_string_pretty(doc)?;
    fs::write(&path, text)?;
    reload();
    Ok(path)
}

/// True if package is in the feed cache.
#[must_use]
pub fn is_feed_blocklisted(ecosystem: Ecosystem, package_name: &str) -> bool {
    state()
        .lock()
        .map(|g| g.sets.contains(ecosystem, package_name))
        .unwrap_or(false)
}

/// Age of the cache file based on file mtime (days).
#[must_use]
pub fn cache_age_days() -> Option<u64> {
    let path = cache_path();
    if !path.is_file() {
        return None;
    }
    let meta = fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let elapsed = SystemTime::now().duration_since(modified).ok()?;
    Some(elapsed.as_secs() / 86_400)
}

/// Missing cache or age > [`MAX_CACHE_AGE_DAYS`].
#[must_use]
pub fn is_stale() -> bool {
    match cache_age_days() {
        None => true,
        Some(days) => days > MAX_CACHE_AGE_DAYS,
    }
}

/// Diagnostics for status / update-db output.
#[must_use]
pub fn status_snapshot() -> serde_json::Value {
    let path = cache_path();
    let guard = state().lock().ok();
    let entries = guard.as_ref().map_or(0, |g| g.sets.total());
    let sources = guard.as_ref().map_or_else(Vec::new, |g| g.sources.clone());
    let updated_at = guard.as_ref().and_then(|g| g.updated_at.clone());
    let errors = guard.as_ref().map_or_else(Vec::new, |g| g.errors.clone());
    let age = cache_age_days();
    serde_json::json!({
        "cache_path": path,
        "exists": path.is_file(),
        "entries": entries,
        "sources": sources,
        "updated_at": updated_at,
        "age_days": age,
        "stale": is_stale(),
        "max_age_days": MAX_CACHE_AGE_DAYS,
        "errors": errors,
    })
}

/// Human-readable stale warning, if any.
#[must_use]
pub fn stale_warning() -> Option<String> {
    if !is_stale() {
        return None;
    }
    match cache_age_days() {
        None => Some(format!(
            "Feed cache missing — no name denylist from feeds. Run \
             `pkg-guard update-db --feed <url>` (refresh at least every {MAX_CACHE_AGE_DAYS} days)"
        )),
        Some(days) => Some(format!(
            "Feed cache is {days} days old (max {MAX_CACHE_AGE_DAYS}) — run `pkg-guard update-db --feed <url>`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_path_under_cache_dir() {
        let p = cache_path();
        assert!(p.ends_with("blocklist-cache.json"));
    }

    #[test]
    fn test_max_age_constant() {
        assert_eq!(MAX_CACHE_AGE_DAYS, 7);
    }

    #[test]
    #[serial_test::serial]
    fn test_write_reload_stale_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("pkg-guard-fc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);

        // missing → stale
        reload();
        assert!(is_stale());
        assert!(stale_warning().is_some());
        assert!(cache_age_days().is_none());
        assert!(!is_feed_blocklisted(Ecosystem::Python, "x"));

        let mut doc = BlocklistDocument::default();
        doc.python = vec!["feed-evil".into()];
        doc.sources = vec!["t".into()];
        doc.updated_at = Some("unix:1".into());
        doc.normalize();
        write_cache(&doc).unwrap();
        assert!(is_feed_blocklisted(Ecosystem::Python, "feed-evil"));
        assert!(cache_age_days().is_some());
        let snap = status_snapshot();
        assert_eq!(snap["exists"], true);

        // corrupt cache
        fs::write(cache_path(), "not-json").unwrap();
        reload();
        let snap = status_snapshot();
        assert!(!snap["errors"].as_array().unwrap().is_empty());

        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        reload();
        let _ = fs::remove_dir_all(&dir);
    }
}
