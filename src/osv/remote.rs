//! Live OSV.dev HTTP API client.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tracing::debug;

use super::{map_vuln, osv_ecosystem, osv_package_name, OsvQueryResult, OsvVuln};
use crate::data::Ecosystem;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to create OSV HTTP client")
}

/// Query OSV API for a single package version.
pub async fn query_package(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
) -> Result<OsvQueryResult> {
    let client = http_client()?;
    let eco = osv_ecosystem(ecosystem);
    let name = osv_package_name(package_name);

    let body = serde_json::json!({
        "version": version,
        "package": {
            "name": name,
            "ecosystem": eco,
        }
    });

    debug!("OSV remote query {eco}/{name}@{version}");

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
        source: Some("online".into()),
    })
}

/// Query OSV API for many package versions (batch).
pub async fn query_batch(items: &[(Ecosystem, String, String)]) -> Result<Vec<OsvQueryResult>> {
    if items.is_empty() {
        return Ok(vec![]);
    }

    let client = http_client()?;
    let queries: Vec<serde_json::Value> = items
        .iter()
        .map(|(eco, name, ver)| {
            let eco_s = osv_ecosystem(*eco);
            let pkg = osv_package_name(name);
            serde_json::json!({
                "version": ver,
                "package": { "name": pkg, "ecosystem": eco_s }
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });
    debug!("OSV remote querybatch ({} items)", items.len());

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
        let pkg = osv_package_name(name);
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
            source: Some("online".into()),
        });
    }

    Ok(out)
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
