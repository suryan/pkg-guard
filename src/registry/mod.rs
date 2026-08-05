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
fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("pkg-guard/0.1.0")
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
    latest_version: Option<String>,
    p: Option<String>,
    timestamp: Option<u64>,
    version_count: Option<u64>,
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

    let url = if let Some(v) = version {
        format!(
            "https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}+AND+v:{v}&rows=1&wt=json"
        )
    } else {
        format!(
            "https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
        )
    };

    debug!("Fetching Maven Central metadata: {url}");

    let response = client.get(&url).send().await?;
    let response = response.error_for_status()?;
    let data: MavenSearchResponse = response.json().await?;

    if data.response.num_found == 0 || data.response.docs.is_empty() {
        return Ok(serde_json::json!({
            "exists": false,
            "error": format!("Package '{package_name}' not found on Maven Central")
        }));
    }

    let doc = &data.response.docs[0];

    Ok(serde_json::json!({
        "exists": true,
        "registry": "maven_central",
        "group_id": doc.g,
        "artifact_id": doc.a,
        "latest_version": doc.latest_version,
        "packaging": doc.p,
        "timestamp": doc.timestamp,
        "version_count": doc.version_count,
    }))
}
