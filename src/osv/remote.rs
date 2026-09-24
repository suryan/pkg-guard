//! Live OSV.dev HTTP API client.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use serde::Deserialize;
use tracing::debug;

use super::{
    map_vuln, min_clear_version, osv_ecosystem, osv_package_name, vuln_spec, AffectedSpec,
    OsvQueryResult, OsvVuln,
};
use crate::data::Ecosystem;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
/// Parallel `GET /v1/vulns/{id}` requests when hydrating batch results.
const HYDRATE_CONCURRENCY: usize = 8;
/// Re-query rounds when a candidate upgrade is itself affected.
const MAX_VERIFY_ROUNDS: usize = 3;

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

    let vulns = payload.vulns.unwrap_or_default();
    let specs: Vec<AffectedSpec> = vulns.iter().map(|v| vuln_spec(v, &name, eco)).collect();
    let advisories: Vec<_> = vulns
        .iter()
        .map(|v| map_vuln(v, &name, version, eco))
        .collect();
    let item = (ecosystem, name.clone(), version.to_string());
    let recommended_version = recommend(&client, &[item], vec![specs], &mut HashMap::new())
        .await
        .pop()
        .flatten();

    Ok(OsvQueryResult {
        package: name,
        version: version.to_string(),
        ecosystem: eco.to_string(),
        advisories,
        error: None,
        source: Some("online".into()),
        recommended_version,
    })
}

/// Query OSV API for many package versions (batch).
///
/// `querybatch` returns only advisory ids, so each unique id is fetched once
/// for severity, summary, and fixed versions.
pub async fn query_batch(items: &[(Ecosystem, String, String)]) -> Result<Vec<OsvQueryResult>> {
    if items.is_empty() {
        return Ok(vec![]);
    }

    let client = http_client()?;
    let ids = batch_ids(&client, items).await?;
    let mut vulns: HashMap<String, OsvVuln> = HashMap::new();
    hydrate(&client, ids.iter().flatten(), &mut vulns).await;

    let mut out = Vec::with_capacity(items.len());
    let mut specs = Vec::with_capacity(items.len());
    for ((eco, name, ver), item_ids) in items.iter().zip(&ids) {
        let eco_s = osv_ecosystem(*eco);
        let pkg = osv_package_name(name);
        let records: Vec<OsvVuln> = item_ids
            .iter()
            .map(|id| {
                vulns.get(id).cloned().unwrap_or_else(|| OsvVuln {
                    id: Some(id.clone()),
                    ..OsvVuln::default()
                })
            })
            .collect();
        specs.push(
            records
                .iter()
                .map(|v| vuln_spec(v, &pkg, eco_s))
                .collect::<Vec<_>>(),
        );
        out.push(OsvQueryResult {
            package: pkg.clone(),
            version: ver.clone(),
            ecosystem: eco_s.to_string(),
            advisories: records
                .iter()
                .map(|v| map_vuln(v, &pkg, ver, eco_s))
                .collect(),
            error: None,
            source: Some("online".into()),
            recommended_version: None,
        });
    }

    let recs = recommend(&client, items, specs, &mut vulns).await;
    for (r, rec) in out.iter_mut().zip(recs) {
        r.recommended_version = rec;
    }
    Ok(out)
}

/// Advisory ids affecting each item, in item order.
async fn batch_ids(
    client: &reqwest::Client,
    items: &[(Ecosystem, String, String)],
) -> Result<Vec<Vec<String>>> {
    let queries: Vec<serde_json::Value> = items
        .iter()
        .map(|(eco, name, ver)| {
            serde_json::json!({
                "version": ver,
                "package": { "name": osv_package_name(name), "ecosystem": osv_ecosystem(*eco) }
            })
        })
        .collect();
    debug!("OSV remote querybatch ({} items)", items.len());

    let response = client
        .post(OSV_BATCH_URL)
        .json(&serde_json::json!({ "queries": queries }))
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

    let results = payload.results.unwrap_or_default();
    Ok((0..items.len())
        .map(|i| {
            results
                .get(i)
                .and_then(|r| r.vulns.as_ref())
                .map(|v| v.iter().filter_map(|x| x.id.clone()).collect())
                .unwrap_or_default()
        })
        .collect())
}

/// Fetch full records for ids not already in `cache` (failures are skipped;
/// callers fall back to id-only advisories).
async fn hydrate<'a>(
    client: &reqwest::Client,
    ids: impl Iterator<Item = &'a String>,
    cache: &mut HashMap<String, OsvVuln>,
) {
    let wanted: HashSet<String> = ids.filter(|id| !cache.contains_key(*id)).cloned().collect();
    let fetched: Vec<(String, Result<OsvVuln>)> = futures_util::stream::iter(wanted)
        .map(|id| async move {
            let res = async {
                client
                    .get(format!("{OSV_VULN_URL}/{id}"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<OsvVuln>()
                    .await
            }
            .await
            .map_err(|e| anyhow!("{e}"));
            (id, res)
        })
        .buffer_unordered(HYDRATE_CONCURRENCY)
        .collect()
        .await;
    for (id, res) in fetched {
        match res {
            Ok(v) => {
                cache.insert(id, v);
            }
            Err(e) => debug!("OSV vuln {id}: {e}"),
        }
    }
}

/// Lowest clean version per item, verified against OSV.
///
/// The API only returns advisories affecting the queried version, so a
/// candidate computed from them may be hit by an advisory introduced later.
/// Each candidate is re-queried; new hits are folded in and the candidate
/// recomputed. Unverifiable candidates yield `None` rather than a guess.
async fn recommend(
    client: &reqwest::Client,
    items: &[(Ecosystem, String, String)],
    mut specs: Vec<Vec<AffectedSpec>>,
    cache: &mut HashMap<String, OsvVuln>,
) -> Vec<Option<String>> {
    let mut out = vec![None; items.len()];
    let mut pending: Vec<usize> = (0..items.len()).filter(|&i| !specs[i].is_empty()).collect();
    for _ in 0..MAX_VERIFY_ROUNDS {
        let candidates: Vec<(usize, String)> = pending
            .iter()
            .filter_map(|&i| {
                let refs: Vec<&AffectedSpec> = specs[i].iter().collect();
                min_clear_version(&items[i].2, &refs).map(|c| (i, c))
            })
            .collect();
        if candidates.is_empty() {
            break;
        }
        let queries: Vec<_> = candidates
            .iter()
            .map(|(i, c)| (items[*i].0, items[*i].1.clone(), c.clone()))
            .collect();
        let Ok(hits) = batch_ids(client, &queries).await else {
            break;
        };
        hydrate(client, hits.iter().flatten(), cache).await;
        pending.clear();
        for ((i, candidate), ids) in candidates.into_iter().zip(hits) {
            if ids.is_empty() {
                out[i] = Some(candidate);
                continue;
            }
            let eco = osv_ecosystem(items[i].0);
            let name = osv_package_name(&items[i].1);
            let before = specs[i].len();
            specs[i].extend(
                ids.iter()
                    .filter_map(|id| cache.get(id))
                    .map(|v| vuln_spec(v, &name, eco)),
            );
            if specs[i].len() > before {
                pending.push(i);
            }
        }
    }
    out
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
