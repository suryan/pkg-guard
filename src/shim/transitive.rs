//! Bounded transitive dependency resolution for shim gates (`uvx` / `npx`).
//!
//! Resolves direct + nested runtime deps from registry metadata (not a full solver).
//! Limits: max depth, max packages, network timeouts.

use std::collections::{HashSet, VecDeque};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tracing::debug;

use super::PackageRef;
use crate::data::Ecosystem;

const MAX_DEPTH: u32 = 3;
const MAX_PACKAGES: usize = 80;

/// Expand `roots` with transitive runtime dependencies (best-effort).
pub async fn expand_with_transitive(
    ecosystem: Ecosystem,
    roots: &[PackageRef],
) -> Result<Vec<PackageRef>> {
    if roots.is_empty() {
        return Ok(vec![]);
    }
    match ecosystem {
        Ecosystem::Python => expand_pypi(roots).await,
        Ecosystem::Npm => expand_npm(roots).await,
        Ecosystem::Java | Ecosystem::Cargo => Ok(roots.to_vec()), // not used for uvx/npx
    }
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("HTTP client for transitive resolve")
}

async fn expand_pypi(roots: &[PackageRef]) -> Result<Vec<PackageRef>> {
    let client = http_client()?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<PackageRef> = Vec::new();
    let mut q: VecDeque<(PackageRef, u32)> = VecDeque::new();

    for r in roots {
        let key = r.name.to_ascii_lowercase();
        if seen.insert(key) {
            q.push_back((r.clone(), 0));
            out.push(r.clone());
        }
    }

    while let Some((pkg, depth)) = q.pop_front() {
        if depth >= MAX_DEPTH || out.len() >= MAX_PACKAGES {
            break;
        }
        let version = match &pkg.version {
            Some(v) => v.clone(),
            None => match pypi_latest_version(&client, &pkg.name).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("pypi latest for {}: {e}", pkg.name);
                    continue;
                }
            },
        };
        let deps = match pypi_requires(&client, &pkg.name, &version).await {
            Ok(d) => d,
            Err(e) => {
                debug!("pypi requires for {}@{version}: {e}", pkg.name);
                continue;
            }
        };
        for dep_name in deps {
            if out.len() >= MAX_PACKAGES {
                break;
            }
            let key = dep_name.to_ascii_lowercase();
            if seen.insert(key) {
                let child = PackageRef {
                    name: dep_name,
                    version: None, // version resolved lazily when we fetch its requires
                };
                out.push(child.clone());
                q.push_back((child, depth + 1));
            }
        }
    }
    Ok(out)
}

async fn pypi_latest_version(client: &reqwest::Client, name: &str) -> Result<String> {
    let url = format!("https://pypi.org/pypi/{name}/json");
    let data: Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("pypi: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("pypi status: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("pypi json: {e}"))?;
    data.get("info")
        .and_then(|i| i.get("version"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("no version for {name}"))
}

async fn pypi_requires(client: &reqwest::Client, name: &str, version: &str) -> Result<Vec<String>> {
    let url = format!("https://pypi.org/pypi/{name}/{version}/json");
    let data: Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("pypi: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("pypi status: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("pypi json: {e}"))?;

    let mut out = Vec::new();
    if let Some(reqs) = data
        .get("info")
        .and_then(|i| i.get("requires_dist"))
        .and_then(Value::as_array)
    {
        for r in reqs {
            let Some(s) = r.as_str() else { continue };
            // Skip env-marker-only extras that are clearly optional: rough filter
            if s.contains("extra ==") {
                continue;
            }
            if let Some(dep) = pep508_name(s) {
                out.push(dep);
            }
        }
    }
    Ok(out)
}

/// `requests>=2.0; python_version>="3"` → `requests`
fn pep508_name(spec: &str) -> Option<String> {
    let s = spec.split(';').next()?.trim();
    let s = s.split('[').next()?.trim();
    let name: String = s
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

async fn expand_npm(roots: &[PackageRef]) -> Result<Vec<PackageRef>> {
    let client = http_client()?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<PackageRef> = Vec::new();
    let mut q: VecDeque<(PackageRef, u32)> = VecDeque::new();

    for r in roots {
        let key = r.name.clone();
        if seen.insert(key) {
            q.push_back((r.clone(), 0));
            out.push(r.clone());
        }
    }

    while let Some((pkg, depth)) = q.pop_front() {
        if depth >= MAX_DEPTH || out.len() >= MAX_PACKAGES {
            break;
        }
        let version = match &pkg.version {
            Some(v) => v.clone(),
            None => match npm_latest_version(&client, &pkg.name).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("npm latest for {}: {e}", pkg.name);
                    continue;
                }
            },
        };
        let deps = match npm_dependencies(&client, &pkg.name, &version).await {
            Ok(d) => d,
            Err(e) => {
                debug!("npm deps for {}@{version}: {e}", pkg.name);
                continue;
            }
        };
        for (dep_name, dep_ver) in deps {
            if out.len() >= MAX_PACKAGES {
                break;
            }
            if seen.insert(dep_name.clone()) {
                // range strings like ^1.0.0 — keep as None for OSV (name-only blocklist still works)
                let ver = if dep_ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    Some(dep_ver)
                } else {
                    None
                };
                let child = PackageRef {
                    name: dep_name,
                    version: ver,
                };
                out.push(child.clone());
                q.push_back((child, depth + 1));
            }
        }
    }
    Ok(out)
}

async fn npm_latest_version(client: &reqwest::Client, name: &str) -> Result<String> {
    let url = format!("https://registry.npmjs.org/{name}");
    let data: Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("npm: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("npm status: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("npm json: {e}"))?;
    data.get("dist-tags")
        .and_then(|d| d.get("latest"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("no latest for {name}"))
}

async fn npm_dependencies(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Result<Vec<(String, String)>> {
    let enc = name; // scoped packages work with slash in URL path
    let url = format!("https://registry.npmjs.org/{enc}/{version}");
    let data: Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("npm: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("npm status: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("npm json: {e}"))?;

    let mut out = Vec::new();
    if let Some(deps) = data.get("dependencies").and_then(Value::as_object) {
        for (k, v) in deps {
            if let Some(ver) = v.as_str() {
                out.push((k.clone(), ver.to_string()));
            }
        }
    }
    Ok(out)
}

/// Env toggle (default **on**).
#[must_use]
pub fn transitive_enabled() -> bool {
    !matches!(
        std::env::var("PKG_GUARD_SHIM_TRANSITIVE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "off" | "no"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pep508_name() {
        assert_eq!(
            pep508_name("requests>=2.0; python_version>=\"3\"").as_deref(),
            Some("requests")
        );
        assert_eq!(pep508_name("Foo[extra]==1.0").as_deref(), Some("Foo"));
        assert_eq!(pep508_name("").as_deref(), None);
    }

    #[test]
    fn test_transitive_enabled_default() {
        std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
        assert!(transitive_enabled());
        std::env::set_var("PKG_GUARD_SHIM_TRANSITIVE", "0");
        assert!(!transitive_enabled());
        std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
    }

    #[tokio::test]
    async fn test_expand_pypi_requests_has_deps() {
        let roots = vec![PackageRef {
            name: "requests".into(),
            version: Some("2.31.0".into()),
        }];
        let expanded = expand_with_transitive(Ecosystem::Python, &roots)
            .await
            .expect("pypi expand");
        assert!(
            expanded.len() > 1,
            "expected transitive deps, got {expanded:?}"
        );
        assert!(expanded.iter().any(|p| p.name == "requests"));
        // well-known dep of requests
        assert!(
            expanded.iter().any(|p| {
                let n = p.name.to_ascii_lowercase();
                n == "urllib3" || n == "certifi" || n == "idna" || n == "charset-normalizer"
            }),
            "deps: {:?}",
            expanded.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_expand_npm_left_pad() {
        let roots = vec![PackageRef {
            name: "left-pad".into(),
            version: Some("1.3.0".into()),
        }];
        let expanded = expand_with_transitive(Ecosystem::Npm, &roots)
            .await
            .expect("npm expand");
        assert!(!expanded.is_empty());
        assert!(expanded.iter().any(|p| p.name == "left-pad"));
    }

    #[tokio::test]
    async fn test_expand_empty_and_cargo_passthrough() {
        assert!(expand_with_transitive(Ecosystem::Python, &[])
            .await
            .unwrap()
            .is_empty());
        let roots = vec![PackageRef {
            name: "serde".into(),
            version: Some("1.0.0".into()),
        }];
        let cargo = expand_with_transitive(Ecosystem::Cargo, &roots)
            .await
            .unwrap();
        assert_eq!(cargo.len(), 1);
    }
}
