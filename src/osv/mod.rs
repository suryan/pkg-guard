//! OSV.dev advisory client — version-aware CVE / malware lookups.
//!
//! Uses `POST https://api.osv.dev/v1/query` and `/v1/querybatch`.
//! Ecosystems map: python → `PyPI`, npm → `npm`, java → `Maven`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::data::Ecosystem;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

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

fn osv_ecosystem(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Python => "PyPI",
        Ecosystem::Npm => "npm",
        Ecosystem::Java => "Maven",
    }
}

/// Maven OSV names are typically `groupId:artifactId` (same string form we use).
fn osv_package_name(_eco: Ecosystem, package_name: &str) -> String {
    package_name.to_string()
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to create OSV HTTP client")
}

/// Query OSV for a single package version.
///
/// # Errors
/// Returns an error on transport/parse failures (caller may degrade gracefully).
pub async fn query_package(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
) -> Result<OsvQueryResult> {
    let client = http_client()?;
    let eco = osv_ecosystem(ecosystem);
    let name = osv_package_name(ecosystem, package_name);

    let body = serde_json::json!({
        "version": version,
        "package": {
            "name": name,
            "ecosystem": eco,
        }
    });

    debug!("OSV query {eco}/{name}@{version}");

    let response = client
        .post(OSV_QUERY_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("OSV request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(anyhow!("OSV returned HTTP {}", response.status()));
    }

    let payload: OsvResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("OSV JSON parse failed: {e}"))?;

    let advisories = payload
        .vulns
        .unwrap_or_default()
        .into_iter()
        .map(|v| map_vuln(&v, &name, version, eco))
        .collect();

    Ok(OsvQueryResult {
        package: name,
        version: version.to_string(),
        ecosystem: eco.to_string(),
        advisories,
        error: None,
    })
}

/// Query OSV for many package versions (batch). Failed transport → error;
/// empty vulns per item is fine.
///
/// # Errors
/// Returns an error if the batch request fails entirely.
pub async fn query_batch(items: &[(Ecosystem, String, String)]) -> Result<Vec<OsvQueryResult>> {
    if items.is_empty() {
        return Ok(vec![]);
    }

    let client = http_client()?;
    let queries: Vec<serde_json::Value> = items
        .iter()
        .map(|(eco, name, ver)| {
            let eco_s = osv_ecosystem(*eco);
            let pkg = osv_package_name(*eco, name);
            serde_json::json!({
                "version": ver,
                "package": { "name": pkg, "ecosystem": eco_s }
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });
    debug!("OSV querybatch ({} items)", items.len());

    let response = client
        .post(OSV_BATCH_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("OSV batch request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(anyhow!("OSV batch returned HTTP {}", response.status()));
    }

    let payload: OsvBatchResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("OSV batch JSON parse failed: {e}"))?;

    let results_raw = payload.results.unwrap_or_default();
    let mut out = Vec::with_capacity(items.len());

    for (i, (eco, name, ver)) in items.iter().enumerate() {
        let eco_s = osv_ecosystem(*eco);
        let pkg = osv_package_name(*eco, name);
        let vulns = results_raw
            .get(i)
            .and_then(|r| r.vulns.clone())
            .unwrap_or_default();
        let advisories = vulns
            .into_iter()
            .map(|v| map_vuln(&v, &pkg, ver, eco_s))
            .collect();
        out.push(OsvQueryResult {
            package: pkg,
            version: ver.clone(),
            ecosystem: eco_s.to_string(),
            advisories,
            error: None,
        });
    }

    Ok(out)
}

fn map_vuln(v: &OsvVuln, package: &str, version: &str, ecosystem: &str) -> OsvAdvisory {
    let id = v.id.clone().unwrap_or_else(|| "UNKNOWN".to_string());
    let is_malware = id.starts_with("MAL-")
        || v.database_specific
            .as_ref()
            .and_then(|d| d.get("malicious"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    let severity = severity_from_vuln(v, is_malware);
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

fn severity_from_vuln(v: &OsvVuln, is_malware: bool) -> String {
    if is_malware {
        return "CRITICAL".to_string();
    }
    if let Some(sevs) = &v.severity {
        for s in sevs {
            if let Some(score) = &s.score {
                // CVSS vector often contains /AV: — try numeric score field variants
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
    // database_specific severity
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

#[derive(Debug, Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Option<Vec<OsvBatchItem>>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchItem {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvVuln {
    id: Option<String>,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    type_: Option<String>,
    score: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_ecosystem_mapping() {
        assert_eq!(osv_ecosystem(Ecosystem::Python), "PyPI");
        assert_eq!(osv_ecosystem(Ecosystem::Npm), "npm");
        assert_eq!(osv_ecosystem(Ecosystem::Java), "Maven");
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
}
