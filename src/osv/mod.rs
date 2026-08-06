//! OSV advisory lookups — **local dump preferred**, live API fallback.
//!
//! ## Modes (`PKG_GUARD_OSV_MODE`)
//! - `auto` (default): use local index when present; fall back to api.osv.dev
//! - `local`: only the dump built by `pkg-guard osv update`
//! - `online`: only the live API (previous behaviour)
//!
//! ## Local data
//! Per-ecosystem zips from
//! `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`
//! are downloaded and indexed under `~/.cache/pkg-guard/osv/`.

mod local;
mod remote;
mod update;
mod version;

pub use local::{has_index, status_snapshot};
pub use update::update_osv;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::data::Ecosystem;

/// One vulnerability from OSV relevant to a package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAdvisory {
    /// OSV id (e.g. GHSA-…, CVE-…, MAL-…)
    pub id: String,
    /// Short summary
    #[serde(default)]
    pub summary: String,
    /// Severity label when known (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN)
    pub severity: String,
    /// True when id looks like malware (MAL-*) rather than a typical CVE
    pub is_malware: bool,
    /// Package that was queried
    pub package: String,
    /// Version that was queried
    pub version: String,
    /// Ecosystem string used in the OSV query
    pub ecosystem: String,
    /// Optional details URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
}

/// Aggregate result of an OSV query for one package.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvQueryResult {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub advisories: Vec<OsvAdvisory>,
    pub error: Option<String>,
    /// `local` or `online` when known
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl OsvQueryResult {
    #[must_use]
    pub fn has_malware(&self) -> bool {
        self.advisories.iter().any(|a| a.is_malware)
    }

    #[must_use]
    pub fn has_critical_or_high(&self) -> bool {
        self.advisories
            .iter()
            .any(|a| matches!(a.severity.as_str(), "CRITICAL" | "HIGH") || a.is_malware)
    }
}

/// How OSV lookups are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsvMode {
    /// Local index if available, else live API.
    Auto,
    /// Local dump only.
    Local,
    /// Live api.osv.dev only.
    Online,
}

impl OsvMode {
    /// Read `PKG_GUARD_OSV_MODE` (`auto`|`local`|`online`).
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("PKG_GUARD_OSV_MODE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "local" | "offline" | "dump" => Self::Local,
            "online" | "remote" | "api" => Self::Online,
            _ => Self::Auto,
        }
    }

    /// Stable string for JSON / status (`auto`, `local`, `online`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Local => "local",
            Self::Online => "online",
        }
    }
}

pub(crate) fn osv_ecosystem(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Python => "PyPI",
        Ecosystem::Npm => "npm",
        Ecosystem::Java => "Maven",
        Ecosystem::Cargo => "crates.io",
    }
}

pub(crate) fn osv_package_name(package_name: &str) -> String {
    package_name.to_string()
}

/// Shared severity fields from dump or API vuln objects.
pub(crate) struct OsvVulnLike {
    pub severity: Option<Vec<OsvSeverity>>,
    pub database_specific: Option<serde_json::Value>,
}

pub(crate) fn map_severity_from_raw(v: &OsvVulnLike, is_malware: bool) -> String {
    if is_malware {
        return "CRITICAL".to_string();
    }
    if let Some(sevs) = &v.severity {
        for s in sevs {
            if let Some(score) = &s.score {
                if let Ok(n) = score.parse::<f64>() {
                    return cvss_label(n);
                }
            }
            if let Some(t) = &s.type_ {
                if t.to_uppercase().contains("CRITICAL") {
                    return "CRITICAL".to_string();
                }
            }
        }
    }
    if let Some(ds) = &v.database_specific {
        if let Some(s) = ds.get("severity").and_then(serde_json::Value::as_str) {
            return s.to_uppercase();
        }
    }
    "UNKNOWN".to_string()
}

fn cvss_label(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".to_string()
    } else if score >= 7.0 {
        "HIGH".to_string()
    } else if score >= 4.0 {
        "MEDIUM".to_string()
    } else if score > 0.0 {
        "LOW".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

/// API / dump vuln shape used by remote mapping.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OsvVuln {
    pub id: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OsvSeverity {
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub score: Option<String>,
}

pub(crate) fn map_vuln(v: &OsvVuln, package: &str, version: &str, ecosystem: &str) -> OsvAdvisory {
    let id = v.id.clone().unwrap_or_else(|| "UNKNOWN".to_string());
    let is_malware = id.starts_with("MAL-")
        || v.database_specific
            .as_ref()
            .and_then(|d| d.get("malicious"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    let severity = map_severity_from_raw(
        &OsvVulnLike {
            severity: v.severity.clone(),
            database_specific: v.database_specific.clone(),
        },
        is_malware,
    );
    let summary = v
        .summary
        .clone()
        .or_else(|| v.details.clone())
        .unwrap_or_else(|| id.clone())
        .chars()
        .take(280)
        .collect();

    OsvAdvisory {
        id: id.clone(),
        summary,
        severity,
        is_malware,
        package: package.to_string(),
        version: version.to_string(),
        ecosystem: ecosystem.to_string(),
        details_url: Some(format!("https://osv.dev/vulnerability/{id}")),
    }
}

fn local_usable(ecosystem: Ecosystem) -> bool {
    has_index(ecosystem)
}

/// Query OSV for a single package version (local dump and/or live API).
///
/// # Errors
/// Returns an error when the selected mode cannot produce a result.
pub async fn query_package(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
) -> Result<OsvQueryResult> {
    match OsvMode::from_env() {
        OsvMode::Online => remote::query_package(ecosystem, package_name, version).await,
        OsvMode::Local => local::query_package(ecosystem, package_name, version),
        OsvMode::Auto => {
            if local_usable(ecosystem) {
                match local::query_package(ecosystem, package_name, version) {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        tracing::warn!("Local OSV failed ({e}); falling back to online API");
                        remote::query_package(ecosystem, package_name, version).await
                    }
                }
            } else {
                remote::query_package(ecosystem, package_name, version).await
            }
        }
    }
}

/// Query OSV for many package versions.
///
/// # Errors
/// Returns an error if the configured backend fails entirely.
pub async fn query_batch(items: &[(Ecosystem, String, String)]) -> Result<Vec<OsvQueryResult>> {
    if items.is_empty() {
        return Ok(vec![]);
    }
    match OsvMode::from_env() {
        OsvMode::Online => remote::query_batch(items).await,
        OsvMode::Local => local::query_batch(items),
        OsvMode::Auto => {
            // Use local only when every required ecosystem has an index;
            // otherwise prefer online for a consistent batch.
            let all_local = items.iter().all(|(e, _, _)| local_usable(*e));
            if all_local {
                match local::query_batch(items) {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        tracing::warn!("Local OSV batch failed ({e}); falling back to online");
                        remote::query_batch(items).await
                    }
                }
            } else {
                remote::query_batch(items).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_ecosystem_mapping() {
        assert_eq!(osv_ecosystem(Ecosystem::Python), "PyPI");
        assert_eq!(osv_ecosystem(Ecosystem::Npm), "npm");
        assert_eq!(osv_ecosystem(Ecosystem::Java), "Maven");
        assert_eq!(osv_ecosystem(Ecosystem::Cargo), "crates.io");
    }

    #[test]
    fn test_cvss_label() {
        assert_eq!(cvss_label(9.1), "CRITICAL");
        assert_eq!(cvss_label(7.5), "HIGH");
        assert_eq!(cvss_label(5.0), "MEDIUM");
        assert_eq!(cvss_label(1.0), "LOW");
    }

    #[test]
    fn test_malware_id_detection() {
        let v = OsvVuln {
            id: Some("MAL-2024-1234".to_string()),
            summary: Some("mal".to_string()),
            details: None,
            severity: None,
            database_specific: None,
        };
        let a = map_vuln(&v, "pkg", "1.0.0", "npm");
        assert!(a.is_malware);
        assert_eq!(a.severity, "CRITICAL");
    }

    #[test]
    fn test_mode_from_env() {
        std::env::set_var("PKG_GUARD_OSV_MODE", "local");
        assert_eq!(OsvMode::from_env(), OsvMode::Local);
        std::env::set_var("PKG_GUARD_OSV_MODE", "online");
        assert_eq!(OsvMode::from_env(), OsvMode::Online);
        std::env::set_var("PKG_GUARD_OSV_MODE", "offline");
        assert_eq!(OsvMode::from_env(), OsvMode::Local);
        std::env::remove_var("PKG_GUARD_OSV_MODE");
        assert_eq!(OsvMode::from_env(), OsvMode::Auto);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_query_prefers_local_in_auto() {
        use local::{
            clear_memory_cache, save_index, save_meta, EcoMeta, EcosystemIndex, IndexedAdvisory,
            IndexedRange, OsvMeta,
        };
        use std::collections::HashMap;

        let dir = std::env::temp_dir().join(format!("pkg-guard-osv-auto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        std::env::set_var("PKG_GUARD_OSV_MODE", "auto");
        clear_memory_cache();

        let mut index = EcosystemIndex::default();
        index.packages.insert(
            "six".into(),
            vec![IndexedAdvisory {
                id: "TEST-LOCAL-SIX".into(),
                summary: "fixture".into(),
                severity: "LOW".into(),
                is_malware: false,
                versions: vec!["1.16.0".into()],
                ranges: vec![],
            }],
        );
        // also need range-only path
        index.packages.insert(
            "range-pkg".into(),
            vec![IndexedAdvisory {
                id: "TEST-RANGE".into(),
                summary: "r".into(),
                severity: "MEDIUM".into(),
                is_malware: false,
                versions: vec![],
                ranges: vec![IndexedRange {
                    introduced: "1.0.0".into(),
                    fixed: None,
                    last_affected: Some("1.5.0".into()),
                }],
            }],
        );
        index.advisory_count = 2;
        index.package_count = 2;
        save_index("PyPI", &index).unwrap();
        let mut meta = OsvMeta {
            updated_at: Some(format!(
                "unix:{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            )),
            ecosystems: HashMap::new(),
            source: "test".into(),
        };
        meta.ecosystems.insert(
            "PyPI".into(),
            EcoMeta {
                advisory_count: 2,
                package_count: 2,
                updated_at: meta.updated_at.clone(),
            },
        );
        save_meta(&meta).unwrap();

        let r = query_package(Ecosystem::Python, "six", "1.16.0")
            .await
            .unwrap();
        assert_eq!(r.source.as_deref(), Some("local"));
        assert_eq!(r.advisories.len(), 1);

        std::env::set_var("PKG_GUARD_OSV_MODE", "local");
        let r = query_package(Ecosystem::Python, "range-pkg", "1.2.0")
            .await
            .unwrap();
        assert_eq!(r.advisories.len(), 1);

        // local mode missing ecosystem index → error
        let err = query_package(Ecosystem::Npm, "left-pad", "1.0.0").await;
        assert!(err.is_err());

        std::env::remove_var("PKG_GUARD_OSV_MODE");
        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        clear_memory_cache();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
