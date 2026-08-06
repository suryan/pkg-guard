//! Registry clients for fetching package metadata without installing.
//!
//! Supports:
//! - `PyPI` (Python Package Index)
//! - `npm` registry
//! - Maven Central (Sonatype)

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::debug;

use crate::data::Ecosystem;

/// Shared HTTP client — reuse across requests.
///
/// Maven Central search is occasionally slow (>15s); keep a generous timeout.
fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .connect_timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {e}"))
}

/// Fetch package metadata from the appropriate registry.
///
/// # Errors
/// Returns an error if the HTTP request fails or the response cannot be parsed.
pub async fn get_package_metadata(
    ecosystem: Ecosystem,
    package_name: &str,
    version: Option<&str>,
) -> Result<Value> {
    match ecosystem {
        Ecosystem::Python => fetch_pypi(package_name, version).await,
        Ecosystem::Npm => fetch_npm(package_name, version).await,
        Ecosystem::Java => fetch_maven(package_name, version).await,
        Ecosystem::Cargo => fetch_crates_io(package_name, version).await,
    }
}

// ─── PyPI ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: Option<String>,
    version: Option<String>,
    summary: Option<String>,
    author: Option<String>,
    author_email: Option<String>,
    home_page: Option<String>,
    license: Option<String>,
    project_urls: Option<Value>,
    requires_dist: Option<Vec<String>>,
    classifiers: Option<Vec<String>>,
    package_url: Option<String>,
}

async fn fetch_pypi(package_name: &str, version: Option<&str>) -> Result<Value> {
    let client = http_client()?;

    let url = match version {
        Some(v) => format!("https://pypi.org/pypi/{package_name}/{v}/json"),
        None => format!("https://pypi.org/pypi/{package_name}/json"),
    };

    debug!("Fetching PyPI metadata: {url}");

    let response = client.get(&url).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!("Package '{package_name}' not found on PyPI")
        }));
    }

    let response = response.error_for_status()?;
    let data: PypiResponse = response.json().await?;

    Ok(serde_json::json!({
        "exists": true,
        "registry": "pypi",
        "name": data.info.name,
        "version": data.info.version,
        "summary": data.info.summary,
        "author": data.info.author,
        "author_email": data.info.author_email,
        "home_page": data.info.home_page,
        "license": data.info.license,
        "project_urls": data.info.project_urls,
        "requires_dist": data.info.requires_dist,
        "classifiers": data.info.classifiers,
        "package_url": data.info.package_url,
    }))
}

// ─── npm ─────────────────────────────────────────────────────────────────────

async fn fetch_npm(package_name: &str, version: Option<&str>) -> Result<Value> {
    let client = http_client()?;

    let url = match version {
        Some(v) => format!("https://registry.npmjs.org/{package_name}/{v}"),
        None => format!("https://registry.npmjs.org/{package_name}"),
    };

    debug!("Fetching npm metadata: {url}");

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!("Package '{package_name}' not found on npm")
        }));
    }

    let response = response.error_for_status()?;
    let data: Value = response.json().await?;

    if version.is_some() {
        // Version-specific response
        let scripts = data
            .get("scripts")
            .cloned()
            .unwrap_or(Value::Object(Map::default()));
        let has_install_scripts = scripts.get("preinstall").is_some()
            || scripts.get("postinstall").is_some()
            || scripts.get("install").is_some();

        return Ok(serde_json::json!({
            "exists": true,
            "registry": "npm",
            "name": data.get("name"),
            "version": data.get("version"),
            "description": data.get("description"),
            "scripts": scripts,
            "dependencies": data.get("dependencies"),
            "has_install_scripts": has_install_scripts,
        }));
    }

    // Full package response
    let dist_tags = data
        .get("dist-tags")
        .cloned()
        .unwrap_or(Value::Object(Map::default()));
    let latest_version = dist_tags
        .get("latest")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let versions = data
        .get("versions")
        .cloned()
        .unwrap_or(Value::Object(Map::default()));
    let latest_info = versions
        .get(latest_version)
        .cloned()
        .unwrap_or(Value::Object(Map::default()));

    let scripts = latest_info
        .get("scripts")
        .cloned()
        .unwrap_or(Value::Object(Map::default()));

    let has_install_scripts = scripts.get("preinstall").is_some()
        || scripts.get("postinstall").is_some()
        || scripts.get("install").is_some();

    Ok(serde_json::json!({
        "exists": true,
        "registry": "npm",
        "name": data.get("name"),
        "latest_version": latest_version,
        "description": data.get("description"),
        "maintainers": data.get("maintainers"),
        "repository": data.get("repository"),
        "license": data.get("license"),
        "scripts": scripts,
        "dependencies": latest_info.get("dependencies"),
        "dev_dependencies": latest_info.get("devDependencies"),
        "has_install_scripts": has_install_scripts,
        "time": data.get("time"),
    }))
}

// ─── crates.io ───────────────────────────────────────────────────────────────

async fn fetch_crates_io(package_name: &str, version: Option<&str>) -> Result<Value> {
    let client = http_client()?;
    let url = match version {
        Some(v) => format!("https://crates.io/api/v1/crates/{package_name}/{v}"),
        None => format!("https://crates.io/api/v1/crates/{package_name}"),
    };
    debug!("Fetching crates.io metadata: {url}");

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!("Package '{package_name}' not found on crates.io")
        }));
    }

    let response = response.error_for_status()?;
    let data: Value = response.json().await?;

    if let Some(v) = version {
        let ver = data.get("version").cloned().unwrap_or(Value::Null);
        return Ok(serde_json::json!({
            "exists": true,
            "registry": "crates.io",
            "name": package_name,
            "version": v,
            "crate": data.get("crate"),
            "version_info": ver,
        }));
    }

    let krate = data
        .get("crate")
        .cloned()
        .unwrap_or(Value::Object(Map::default()));
    Ok(serde_json::json!({
        "exists": true,
        "registry": "crates.io",
        "name": krate.get("name"),
        "latest_version": krate.get("max_version").or_else(|| krate.get("newest_version")),
        "description": krate.get("description"),
        "repository": krate.get("repository"),
        "homepage": krate.get("homepage"),
        "license": krate.get("license"),
        "downloads": krate.get("downloads"),
    }))
}

// ─── Maven Central ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MavenSearchResponse {
    response: MavenResponseBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MavenResponseBody {
    num_found: u64,
    docs: Vec<MavenDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MavenDoc {
    g: Option<String>,
    a: Option<String>,
    /// Present on latest-version search results.
    latest_version: Option<String>,
    /// Present on version-specific search results (`v=...`).
    v: Option<String>,
    p: Option<String>,
    timestamp: Option<u64>,
    version_count: Option<u64>,
}

/// URL-encode a Solr query token (group, artifact, version).
fn encode_solr_token(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            // Version tokens may contain '+' which must be encoded.
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn build_maven_search_url(group_id: &str, artifact_id: &str, version: Option<&str>) -> String {
    let g = encode_solr_token(group_id);
    let a = encode_solr_token(artifact_id);
    match version {
        Some(v) => {
            let v = encode_solr_token(v);
            format!(
                "https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}+AND+v:{v}&rows=1&wt=json"
            )
        }
        None => {
            format!("https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&rows=1&wt=json")
        }
    }
}

async fn fetch_maven(package_name: &str, version: Option<&str>) -> Result<Value> {
    let client = http_client()?;

    // Parse groupId:artifactId
    let parts: Vec<&str> = package_name.split(':').collect();
    if parts.len() != 2 {
        return Ok(serde_json::json!({
            "exists": false,
            "error": "Invalid format. Use groupId:artifactId (e.g., 'org.springframework:spring-core')"
        }));
    }
    let (group_id, artifact_id) = (parts[0], parts[1]);

    match fetch_maven_solr(&client, package_name, group_id, artifact_id, version).await {
        Ok(value) => Ok(value),
        Err(solr_err) => {
            debug!("Maven Solr search failed ({solr_err}); trying repo1 fallback");
            if let Some(v) = version {
                fetch_maven_repo1_fallback(&client, package_name, group_id, artifact_id, v).await
            } else {
                Err(solr_err)
            }
        }
    }
}

async fn fetch_maven_solr(
    client: &Client,
    package_name: &str,
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
) -> Result<Value> {
    let url = build_maven_search_url(group_id, artifact_id, version);
    debug!("Fetching Maven Central metadata: {url}");

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("Maven Central request failed for '{package_name}': {e}"))?;
    let response = response
        .error_for_status()
        .map_err(|e| anyhow!("Maven Central returned an error for '{package_name}': {e}"))?;
    let data: MavenSearchResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse Maven Central response for '{package_name}': {e}"))?;

    if data.response.num_found == 0 || data.response.docs.is_empty() {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!("Package '{package_name}' not found on Maven Central")
        }));
    }

    let doc = &data.response.docs[0];
    // Version-specific docs use `v`; latest-search docs use `latestVersion`.
    let resolved_version = doc
        .v
        .clone()
        .or_else(|| doc.latest_version.clone())
        .or_else(|| version.map(ToString::to_string));

    Ok(serde_json::json!({
        "exists": true,
        "registry": "maven_central",
        "group_id": doc.g,
        "artifact_id": doc.a,
        "version": resolved_version,
        "latest_version": doc.latest_version,
        "packaging": doc.p,
        "timestamp": doc.timestamp,
        "version_count": doc.version_count,
    }))
}

/// Fallback when Solr is unreachable: HEAD the artifact POM on repo1.
async fn fetch_maven_repo1_fallback(
    client: &Client,
    package_name: &str,
    group_id: &str,
    artifact_id: &str,
    version: &str,
) -> Result<Value> {
    let group_path = group_id.replace('.', "/");
    let url = format!(
        "https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
    );
    debug!("Maven repo1 fallback HEAD: {url}");

    let response = client
        .head(&url)
        .send()
        .await
        .map_err(|e| anyhow!("Maven repo1 fallback failed for '{package_name}': {e}"))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!(
                "Package '{package_name}' version '{version}' not found on Maven Central"
            )
        }));
    }

    if !response.status().is_success() {
        return Err(anyhow!(
            "Maven repo1 fallback returned {} for '{package_name}'",
            response.status()
        ));
    }

    Ok(serde_json::json!({
        "exists": true,
        "registry": "maven_central_repo1",
        "group_id": group_id,
        "artifact_id": artifact_id,
        "version": version,
        "pom_url": url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_solr_token_encodes_plus_in_version() {
        let encoded = encode_solr_token("32.1.3-jre");
        assert_eq!(encoded, "32.1.3-jre");
        let with_plus = encode_solr_token("1.0+scala");
        assert!(with_plus.contains("%2B"), "plus should be percent-encoded");
        assert!(!with_plus.contains('+'));
    }

    #[test]
    fn test_build_maven_search_url_versioned() {
        let url = build_maven_search_url("com.google.guava", "guava", Some("32.1.3-jre"));
        assert!(url.contains("g:com.google.guava"));
        assert!(url.contains("a:guava"));
        assert!(url.contains("v:32.1.3-jre"));
        assert!(url.contains("search.maven.org"));
    }

    #[test]
    fn test_build_maven_search_url_latest() {
        let url = build_maven_search_url("org.springframework", "spring-core", None);
        assert!(url.contains("g:org.springframework"));
        assert!(!url.contains("AND+v:"));
    }
}
