//! Local OSV dump index queries (no network).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::version::version_matches_range;
use super::{osv_ecosystem, osv_package_name, OsvAdvisory, OsvQueryResult};
use crate::data::feed_cache;
use crate::data::Ecosystem;

/// Max age (days) before local dump is considered stale in `auto` mode.
pub const MAX_OSV_AGE_DAYS: u64 = 7;

/// Compact advisory stored in the per-ecosystem index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedAdvisory {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub is_malware: bool,
    /// Exact affected versions (when present in the dump).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    /// Simplified ranges: `introduced` + optional `fixed` / `last_affected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<IndexedRange>,
}

/// One introduced/fixed window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedRange {
    #[serde(default = "default_introduced")]
    pub introduced: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

fn default_introduced() -> String {
    "0".into()
}

/// Per-ecosystem package → advisories map.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EcosystemIndex {
    /// Package name → advisories (keys as returned by OSV; `PyPI` lookup is case-insensitive).
    pub packages: HashMap<String, Vec<IndexedAdvisory>>,
    pub advisory_count: usize,
    pub package_count: usize,
}

/// Root meta written next to indexes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvMeta {
    pub updated_at: Option<String>,
    pub ecosystems: HashMap<String, EcoMeta>,
    pub source: String,
}

/// Per-ecosystem meta.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EcoMeta {
    pub advisory_count: usize,
    pub package_count: usize,
    pub updated_at: Option<String>,
    /// HTTP `ETag` from the dump zip (for skip-if-fresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// HTTP `Last-Modified` from the dump zip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// `Content-Length` of the dump zip when last downloaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Dump URL that was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dump_url: Option<String>,
}

fn cache_root() -> PathBuf {
    // Reuse PKG_GUARD_CACHE_DIR parent layout: <cache>/osv
    feed_cache::cache_dir().join("osv")
}

/// Directory for OSV dump indexes.
#[must_use]
pub fn osv_dir() -> PathBuf {
    cache_root()
}

fn meta_path() -> PathBuf {
    osv_dir().join("meta.json")
}

fn index_path(eco: &str) -> PathBuf {
    // ecosystem names may contain '.' (crates.io) — safe as single path segment
    osv_dir().join(format!("{eco}.index.json"))
}

/// Load meta if present.
#[must_use]
pub fn load_meta() -> Option<OsvMeta> {
    let path = meta_path();
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Persist meta.
pub fn save_meta(meta: &OsvMeta) -> Result<()> {
    let dir = osv_dir();
    fs::create_dir_all(&dir)?;
    let text = serde_json::to_string_pretty(meta)?;
    fs::write(meta_path(), text)?;
    Ok(())
}

/// Persist an ecosystem index.
pub fn save_index(eco: &str, index: &EcosystemIndex) -> Result<PathBuf> {
    let dir = osv_dir();
    fs::create_dir_all(&dir)?;
    let path = index_path(eco);
    let text = serde_json::to_string(index).context("serialize OSV index")?;
    fs::write(&path, text)?;
    Ok(path)
}

/// True if local index exists for ecosystem.
#[must_use]
pub fn has_index(eco: Ecosystem) -> bool {
    has_index_str(osv_ecosystem(eco))
}

/// True if local index file exists for an OSV ecosystem name (`PyPI`, `npm`, …).
#[must_use]
pub fn has_index_str(osv_eco: &str) -> bool {
    index_path(osv_eco).is_file()
}

/// Age of local dump in days (from `meta.updated_at` `unix:N` or file mtime).
#[must_use]
pub fn age_days() -> Option<u64> {
    if let Some(meta) = load_meta() {
        if let Some(ref ts) = meta.updated_at {
            if let Some(secs) = ts.strip_prefix("unix:") {
                if let Ok(then) = secs.parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(then);
                    return Some(now.saturating_sub(then) / 86_400);
                }
            }
        }
    }
    let path = meta_path();
    if !path.is_file() {
        return None;
    }
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let elapsed = std::time::SystemTime::now().duration_since(modified).ok()?;
    Some(elapsed.as_secs() / 86_400)
}

/// Missing or older than [`MAX_OSV_AGE_DAYS`].
#[must_use]
pub fn is_stale() -> bool {
    match age_days() {
        None => true,
        Some(d) => d > MAX_OSV_AGE_DAYS,
    }
}

/// Diagnostics for CLI / MCP (local state only — no network).
#[must_use]
pub fn status_snapshot() -> serde_json::Value {
    let meta = load_meta();
    let dir = osv_dir();
    serde_json::json!({
        "osv_dir": dir,
        "exists": dir.is_dir() && meta.is_some(),
        "stale": is_stale(),
        "age_days": age_days(),
        "max_age_days": MAX_OSV_AGE_DAYS,
        "auto_update": super::update::auto_update_enabled(),
        "mode": format!("{:?}", super::OsvMode::from_env()).to_ascii_lowercase(),
        "mode_env": "PKG_GUARD_OSV_MODE=auto|local|online",
        "meta": meta,
        "hints": [
            "Download dumps: pkg-guard osv update  (skips if already latest; --force to redownload)",
            "Scan auto-refreshes dumps when PKG_GUARD_OSV_AUTO_UPDATE is on (default)",
            "Per-ecosystem zips from https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip",
            "auto mode uses local index when present; falls back to api.osv.dev",
        ],
    })
}

// ─── in-memory cache of loaded indexes ───────────────────────────────────────

static INDEX_CACHE: OnceLock<Mutex<HashMap<String, EcosystemIndex>>> = OnceLock::new();

fn index_cache() -> &'static Mutex<HashMap<String, EcosystemIndex>> {
    INDEX_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Drop in-memory indexes (after update).
pub fn clear_memory_cache() {
    if let Ok(mut g) = index_cache().lock() {
        g.clear();
    }
}

fn load_index(eco: &str) -> Result<EcosystemIndex> {
    if let Ok(guard) = index_cache().lock() {
        if let Some(idx) = guard.get(eco) {
            return Ok(EcosystemIndex {
                packages: idx.packages.clone(),
                advisory_count: idx.advisory_count,
                package_count: idx.package_count,
            });
        }
    }

    let path = index_path(eco);
    if !path.is_file() {
        return Err(anyhow!(
            "Local OSV index missing for {eco} at {}. Run: pkg-guard osv update",
            path.display()
        ));
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("read OSV index {}", path.display()))?;
    let index: EcosystemIndex = serde_json::from_str(&text)
        .with_context(|| format!("parse OSV index {}", path.display()))?;

    if let Ok(mut guard) = index_cache().lock() {
        guard.insert(eco.to_string(), clone_index(&index));
    }
    Ok(index)
}

fn clone_index(idx: &EcosystemIndex) -> EcosystemIndex {
    EcosystemIndex {
        packages: idx.packages.clone(),
        advisory_count: idx.advisory_count,
        package_count: idx.package_count,
    }
}

fn package_key(eco: Ecosystem, name: &str) -> String {
    let n = osv_package_name(name);
    match eco {
        Ecosystem::Python => n.to_ascii_lowercase(),
        _ => n,
    }
}

fn lookup_advisories<'a>(
    index: &'a EcosystemIndex,
    eco: Ecosystem,
    name: &str,
) -> Option<&'a [IndexedAdvisory]> {
    let key = package_key(eco, name);
    if let Some(v) = index.packages.get(&key) {
        return Some(v.as_slice());
    }
    // case-insensitive fallback for all
    let lower = key.to_ascii_lowercase();
    index
        .packages
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&lower))
        .map(|(_, v)| v.as_slice())
}

/// Whether an indexed advisory affects `version`.
fn advisory_matches(adv: &IndexedAdvisory, version: &str) -> bool {
    if adv.versions.iter().any(|v| v == version) {
        return true;
    }
    if !adv.ranges.is_empty() {
        return adv.ranges.iter().any(|r| {
            version_matches_range(
                version,
                &r.introduced,
                r.fixed.as_deref(),
                r.last_affected.as_deref(),
            )
        });
    }
    // No versions and no ranges — cannot match a specific version (skip)
    false
}

/// Query the local dump for one package version.
pub fn query_package(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
) -> Result<OsvQueryResult> {
    let eco = osv_ecosystem(ecosystem);
    let name = osv_package_name(package_name);
    let index = load_index(eco)?;
    let mut advisories = Vec::new();

    if let Some(list) = lookup_advisories(&index, ecosystem, &name) {
        for adv in list {
            if advisory_matches(adv, version) {
                advisories.push(OsvAdvisory {
                    id: adv.id.clone(),
                    summary: adv.summary.clone(),
                    severity: adv.severity.clone(),
                    is_malware: adv.is_malware,
                    package: name.clone(),
                    version: version.to_string(),
                    ecosystem: eco.to_string(),
                    details_url: Some(format!("https://osv.dev/vulnerability/{}", adv.id)),
                });
            }
        }
    }

    debug!(
        "OSV local query {eco}/{name}@{version} → {} hit(s)",
        advisories.len()
    );

    Ok(OsvQueryResult {
        package: name,
        version: version.to_string(),
        ecosystem: eco.to_string(),
        advisories,
        error: None,
        source: Some("local".into()),
    })
}

/// Query local dump for many packages.
pub fn query_batch(items: &[(Ecosystem, String, String)]) -> Result<Vec<OsvQueryResult>> {
    let mut out = Vec::with_capacity(items.len());
    for (eco, name, ver) in items {
        out.push(query_package(*eco, name, ver)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_advisory_matches_versions_and_ranges() {
        let adv = IndexedAdvisory {
            id: "TEST-1".into(),
            summary: "x".into(),
            severity: "HIGH".into(),
            is_malware: false,
            versions: vec!["1.0.0".into()],
            ranges: vec![],
        };
        assert!(advisory_matches(&adv, "1.0.0"));
        assert!(!advisory_matches(&adv, "1.0.1"));

        let adv = IndexedAdvisory {
            id: "TEST-2".into(),
            summary: "x".into(),
            severity: "CRITICAL".into(),
            is_malware: true,
            versions: vec![],
            ranges: vec![IndexedRange {
                introduced: "0".into(),
                fixed: Some("2.0.0".into()),
                last_affected: None,
            }],
        };
        assert!(advisory_matches(&adv, "1.9.9"));
        assert!(!advisory_matches(&adv, "2.0.0"));
    }

    #[test]
    #[serial]
    fn test_save_load_query_and_status() {
        let dir = std::env::temp_dir().join(format!("pkg-guard-osv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        clear_memory_cache();

        let mut index = EcosystemIndex::default();
        index.packages.insert(
            "evil-crate".into(),
            vec![IndexedAdvisory {
                id: "MAL-LOCAL-1".into(),
                summary: "bad".into(),
                severity: "CRITICAL".into(),
                is_malware: true,
                versions: vec!["0.1.0".into()],
                ranges: vec![IndexedRange {
                    introduced: "0".into(),
                    fixed: Some("1.0.0".into()),
                    last_affected: None,
                }],
            }],
        );
        index.advisory_count = 1;
        index.package_count = 1;
        save_index("crates.io", &index).unwrap();
        let mut meta = OsvMeta {
            updated_at: Some("unix:1".into()),
            ecosystems: HashMap::new(),
            source: "test".into(),
        };
        meta.ecosystems.insert(
            "crates.io".into(),
            EcoMeta {
                advisory_count: 1,
                package_count: 1,
                updated_at: Some("unix:1".into()),
                ..Default::default()
            },
        );
        save_meta(&meta).unwrap();
        clear_memory_cache();

        assert!(has_index(Ecosystem::Cargo));
        assert!(load_meta().is_some());
        let hit = query_package(Ecosystem::Cargo, "evil-crate", "0.1.0").unwrap();
        assert_eq!(hit.source.as_deref(), Some("local"));
        assert!(hit.has_malware());
        let miss = query_package(Ecosystem::Cargo, "evil-crate", "9.0.0").unwrap();
        assert!(miss.advisories.is_empty());
        let batch =
            query_batch(&[(Ecosystem::Cargo, "evil-crate".into(), "0.1.0".into())]).unwrap();
        assert_eq!(batch.len(), 1);
        let snap = status_snapshot();
        assert_eq!(snap["exists"], true);
        let _ = age_days();
        let _ = is_stale();
        // second load hits memory cache
        let hit2 = query_package(Ecosystem::Cargo, "evil-crate", "0.1.0").unwrap();
        assert!(!hit2.advisories.is_empty());
        // missing index error path
        assert!(query_package(Ecosystem::Java, "g:a", "1").is_err());
        // empty versions+ranges does not match
        assert!(!advisory_matches(
            &IndexedAdvisory {
                id: "X".into(),
                summary: String::new(),
                severity: "UNKNOWN".into(),
                is_malware: false,
                versions: vec![],
                ranges: vec![],
            },
            "1.0.0"
        ));

        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        clear_memory_cache();
        let _ = fs::remove_dir_all(&dir);
    }
}
