//! Transitive dependency resolution for shim gates (`uvx` / `npx`).
//!
//! Resolves nested runtime deps from registry metadata (not a full solver).
//! The crawl runs on the launch hot path, so it is bounded: an overall
//! wall-clock budget, a node cap, a depth cap, bounded fetch concurrency, and
//! an on-disk metadata cache. Anything that could not be verified (failed
//! lookup, non-registry spec, limit hit) is reported in [`Expansion`] rather
//! than silently treated as clean.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

use super::PackageRef;
use crate::data::Ecosystem;

const DEFAULT_BUDGET_MS: u64 = 8_000;
const DEFAULT_MAX_NODES: usize = 1_000;
const DEFAULT_MAX_DEPTH: usize = 16;
const DEFAULT_CONCURRENCY: usize = 16;
const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Limits and endpoints for one expansion.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub budget: Duration,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub concurrency: usize,
    pub pypi_base: String,
    pub npm_base: String,
    /// `None` disables the on-disk cache.
    pub cache_dir: Option<PathBuf>,
    pub cache_ttl: Duration,
}

impl Config {
    /// Read `PKG_GUARD_TRANSITIVE_*` and registry overrides from the environment.
    pub fn from_env() -> Self {
        let ttl = env_num(
            "PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS",
            DEFAULT_CACHE_TTL_SECS,
        );
        Self {
            budget: Duration::from_millis(env_num(
                "PKG_GUARD_TRANSITIVE_BUDGET_MS",
                DEFAULT_BUDGET_MS,
            )),
            max_nodes: env_num("PKG_GUARD_TRANSITIVE_MAX_NODES", DEFAULT_MAX_NODES),
            max_depth: env_num("PKG_GUARD_TRANSITIVE_MAX_DEPTH", DEFAULT_MAX_DEPTH),
            concurrency: env_num("PKG_GUARD_TRANSITIVE_CONCURRENCY", DEFAULT_CONCURRENCY).max(1),
            pypi_base: env_url("PKG_GUARD_PYPI_URL", "https://pypi.org"),
            npm_base: env_url("PKG_GUARD_NPM_REGISTRY", "https://registry.npmjs.org"),
            cache_dir: (ttl > 0).then(|| crate::data::feed_cache::cache_dir().join("transitive")),
            cache_ttl: Duration::from_secs(ttl),
        }
    }
}

fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_url(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Which limit stopped the crawl early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    Budget,
    MaxNodes,
    MaxDepth,
}

/// Result of a transitive expansion, including what could not be verified.
#[derive(Debug, Default)]
pub struct Expansion {
    /// Roots plus every discovered dependency (names are always present, even
    /// for nodes whose own dependencies could not be fetched).
    pub packages: Vec<PackageRef>,
    /// `name: reason` for nodes whose metadata could not be resolved.
    pub unresolved: Vec<String>,
    /// Nodes discovered but not crawled because a limit was hit.
    pub unexpanded: usize,
    pub limit_hit: Option<LimitHit>,
    /// Nodes without an exact version (OSV skipped; name-only checks apply).
    pub unversioned: usize,
}

impl Expansion {
    /// True when every discovered node had its dependencies fetched.
    pub fn is_complete(&self) -> bool {
        self.unresolved.is_empty() && self.unexpanded == 0 && self.limit_hit.is_none()
    }
}

/// Expand `roots` with transitive runtime dependencies using env configuration.
pub async fn expand_with_transitive(
    ecosystem: Ecosystem,
    roots: &[PackageRef],
) -> Result<Expansion> {
    expand_with_config(ecosystem, roots, &Config::from_env()).await
}

/// Expand `roots` with explicit limits / endpoints.
pub(crate) async fn expand_with_config(
    ecosystem: Ecosystem,
    roots: &[PackageRef],
    cfg: &Config,
) -> Result<Expansion> {
    if roots.is_empty() || matches!(ecosystem, Ecosystem::Java | Ecosystem::Cargo) {
        return Ok(Expansion {
            packages: roots.to_vec(),
            unversioned: roots.iter().filter(|p| p.version.is_none()).count(),
            ..Expansion::default()
        });
    }
    let client = http_client()?;
    let mut cache = MetaCache::load(cfg, ecosystem);
    let result = crawl(&client, cfg, ecosystem, roots, &mut cache).await;
    cache.save();
    Ok(result)
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("HTTP client for transitive resolve")
}

struct Node {
    idx: usize,
    depth: usize,
}

/// Dependency metadata for one resolved package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeMeta {
    version: String,
    deps: Vec<DepSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DepSpec {
    name: String,
    /// Exact version when the spec pins one.
    version: Option<String>,
    /// Set when the spec is not resolvable from the registry (git, URL, file…).
    #[serde(default)]
    non_registry: Option<String>,
}

async fn crawl(
    client: &reqwest::Client,
    cfg: &Config,
    eco: Ecosystem,
    roots: &[PackageRef],
    cache: &mut MetaCache,
) -> Expansion {
    let now = tokio::time::Instant::now();
    let deadline = now
        .checked_add(cfg.budget)
        .unwrap_or(now + Duration::from_secs(86_400));
    let mut exp = Expansion::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Node> = VecDeque::new();

    for r in roots {
        if seen.insert(seen_key(eco, &r.name)) {
            queue.push_back(Node {
                idx: exp.packages.len(),
                depth: 0,
            });
            exp.packages.push(r.clone());
        }
    }

    let mut fetched = 0usize;
    let mut inflight = FuturesUnordered::new();
    loop {
        while inflight.len() < cfg.concurrency && fetched < cfg.max_nodes {
            let Some(node) = queue.pop_front() else { break };
            if node.depth >= cfg.max_depth {
                exp.unexpanded += 1;
                exp.limit_hit.get_or_insert(LimitHit::MaxDepth);
                continue;
            }
            fetched += 1;
            let pkg = exp.packages[node.idx].clone();
            let cached = cache.get(&pkg);
            inflight.push(async move {
                let res = match cached {
                    Some(meta) => Ok((meta, false)),
                    None => fetch_meta(client, cfg, eco, &pkg).await.map(|m| (m, true)),
                };
                (node, pkg, res)
            });
        }
        if inflight.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, inflight.next()).await {
            Ok(Some((node, pkg, Ok((meta, fresh))))) => {
                if fresh {
                    cache.put(&pkg, &meta);
                }
                record_children(eco, &node, &pkg, &meta, &mut exp, &mut seen, &mut queue);
            }
            Ok(Some((_, pkg, Err(e)))) => {
                debug!("transitive lookup failed for {}: {e}", pkg.name);
                exp.unresolved.push(format!("{}: {e}", display_ref(&pkg)));
            }
            Ok(None) => break,
            Err(_) => {
                exp.limit_hit = Some(LimitHit::Budget);
                exp.unexpanded += inflight.len();
                break;
            }
        }
    }
    if !queue.is_empty() {
        exp.unexpanded += queue.len();
        exp.limit_hit.get_or_insert(LimitHit::MaxNodes);
    }
    exp.unversioned = exp.packages.iter().filter(|p| p.version.is_none()).count();
    exp
}

fn record_children(
    eco: Ecosystem,
    node: &Node,
    pkg: &PackageRef,
    meta: &NodeMeta,
    exp: &mut Expansion,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<Node>,
) {
    // A tag like `latest` resolves to a concrete version usable for OSV.
    if pkg.version.as_deref().is_some_and(|v| v != meta.version) {
        exp.packages[node.idx].version = Some(meta.version.clone());
    }
    for dep in &meta.deps {
        if !seen.insert(seen_key(eco, &dep.name)) {
            continue;
        }
        let child = PackageRef {
            name: dep.name.clone(),
            version: dep.version.clone(),
        };
        if let Some(spec) = &dep.non_registry {
            exp.unresolved
                .push(format!("{}: non-registry spec {spec}", dep.name));
            exp.packages.push(child);
            continue;
        }
        queue.push_back(Node {
            idx: exp.packages.len(),
            depth: node.depth + 1,
        });
        exp.packages.push(child);
    }
}

fn display_ref(p: &PackageRef) -> String {
    match &p.version {
        Some(v) => format!("{}@{v}", p.name),
        None => p.name.clone(),
    }
}

fn seen_key(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Python => pypi_normalize(name),
        _ => name.to_string(),
    }
}

/// PEP 503 normalisation: lowercase, runs of `-_.` collapse to `-`.
fn pypi_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

async fn fetch_meta(
    client: &reqwest::Client,
    cfg: &Config,
    eco: Ecosystem,
    pkg: &PackageRef,
) -> Result<NodeMeta> {
    match eco {
        Ecosystem::Python => fetch_pypi(client, &cfg.pypi_base, pkg).await,
        _ => fetch_npm(client, &cfg.npm_base, pkg).await,
    }
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value> {
    client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            let mut root: &dyn std::error::Error = &e;
            while let Some(next) = root.source() {
                root = next;
            }
            anyhow!("request failed: {root}")
        })?
        .error_for_status()
        .map_err(|e| anyhow!("{}", e.status().map_or(e.to_string(), |s| s.to_string())))?
        .json()
        .await
        .map_err(|e| anyhow!("invalid JSON: {e}"))
}

async fn fetch_pypi(client: &reqwest::Client, base: &str, pkg: &PackageRef) -> Result<NodeMeta> {
    let name = &pkg.name;
    let url = match &pkg.version {
        Some(v) => format!("{base}/pypi/{name}/{v}/json"),
        None => format!("{base}/pypi/{name}/json"),
    };
    let data = get_json(client, &url).await?;
    let info = data.get("info").ok_or_else(|| anyhow!("missing info"))?;
    let version = info
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing version"))?
        .to_string();
    let deps = info
        .get("requires_dist")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        // Optional extras are not installed unless requested.
        .filter(|s| !s.contains("extra =="))
        .filter_map(pep508_name)
        .map(|name| DepSpec {
            name,
            version: None,
            non_registry: None,
        })
        .collect();
    Ok(NodeMeta { version, deps })
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

async fn fetch_npm(client: &reqwest::Client, base: &str, pkg: &PackageRef) -> Result<NodeMeta> {
    let tag = pkg.version.as_deref().unwrap_or("latest");
    let url = format!("{base}/{}/{tag}", pkg.name);
    let data = get_json(client, &url).await?;
    let version = data
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing version"))?
        .to_string();
    let deps = data
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|spec| npm_dep(k, spec)))
        .collect();
    Ok(NodeMeta { version, deps })
}

/// Interpret an npm dependency spec (`^1.0.0`, `1.2.3`, `npm:real@^2`, git URL…).
fn npm_dep(name: &str, spec: &str) -> DepSpec {
    let spec = spec.trim();
    // Aliases install a *different* package under `name`; audit the real one.
    if let Some(target) = spec.strip_prefix("npm:") {
        let (real, range) = match target.strip_prefix('@') {
            Some(rest) => match rest.split_once('@') {
                Some((n, r)) => (format!("@{n}"), r),
                None => (target.to_string(), ""),
            },
            None => match target.split_once('@') {
                Some((n, r)) => (n.to_string(), r),
                None => (target.to_string(), ""),
            },
        };
        return DepSpec {
            name: real,
            version: is_exact_semver(range).then(|| range.to_string()),
            non_registry: None,
        };
    }
    let non_registry = spec.contains("://")
        || spec.contains('/')
        || ["git", "file:", "link:", "workspace:"]
            .iter()
            .any(|p| spec.starts_with(p));
    DepSpec {
        name: name.to_string(),
        version: is_exact_semver(spec).then(|| spec.to_string()),
        non_registry: non_registry.then(|| spec.to_string()),
    }
}

/// `1.2.3`, `1.2.3-beta.1`, `1.2.3+build` — but not ranges like `1.x` or `^1.2.3`.
fn is_exact_semver(s: &str) -> bool {
    let core = s.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && !s.contains(' ')
}

/// On-disk cache of registry metadata, keyed by `name@version` (or `name@latest`).
struct MetaCache {
    path: Option<PathBuf>,
    ttl_secs: u64,
    entries: HashMap<String, CacheEntry>,
    fresh: HashMap<String, CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    meta: NodeMeta,
}

impl MetaCache {
    fn load(cfg: &Config, eco: Ecosystem) -> Self {
        let path = cfg.cache_dir.as_ref().map(|d| {
            d.join(match eco {
                Ecosystem::Python => "pypi.json",
                _ => "npm.json",
            })
        });
        let entries = path.as_deref().map(read_cache_file).unwrap_or_default();
        Self {
            path,
            ttl_secs: cfg.cache_ttl.as_secs(),
            entries,
            fresh: HashMap::new(),
        }
    }

    fn key(pkg: &PackageRef) -> String {
        format!(
            "{}@{}",
            pkg.name,
            pkg.version.as_deref().unwrap_or("latest")
        )
    }

    fn get(&self, pkg: &PackageRef) -> Option<NodeMeta> {
        self.path.as_ref()?;
        let e = self.entries.get(&Self::key(pkg))?;
        (now_secs().saturating_sub(e.fetched_at) < self.ttl_secs).then(|| e.meta.clone())
    }

    fn put(&mut self, pkg: &PackageRef, meta: &NodeMeta) {
        if self.path.is_some() {
            self.fresh.insert(
                Self::key(pkg),
                CacheEntry {
                    fetched_at: now_secs(),
                    meta: meta.clone(),
                },
            );
        }
    }

    /// Merge fresh entries into the current file (other shims may have written
    /// since load), drop expired ones, and replace atomically.
    fn save(self) {
        let Some(path) = self.path else { return };
        if self.fresh.is_empty() {
            return;
        }
        let now = now_secs();
        let mut merged = read_cache_file(&path);
        merged.extend(self.fresh);
        merged.retain(|_, e| now.saturating_sub(e.fetched_at) < self.ttl_secs);
        if let Err(e) = write_cache_file(&path, &merged) {
            debug!("transitive cache write {}: {e}", path.display());
        }
    }
}

fn read_cache_file(path: &Path) -> HashMap<String, CacheEntry> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_cache_file(path: &Path, entries: &HashMap<String, CacheEntry>) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent dir"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.{}", std::process::id(), now_nanos()));
    std::fs::write(&tmp, serde_json::to_vec(entries)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
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
#[path = "transitive_tests.rs"]
pub(crate) mod tests;
