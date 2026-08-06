//! `pkg-guard update-db` — refresh the feed cache from remote feeds + seed.
//!
//! Default feeds can be set via `PKG_GUARD_FEED_URLS` (comma-separated).
//! Additional URLs can be passed on the CLI. The embedded seed is always merged
//! so offline seed data remains present even if feeds fail.

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use super::blocklist::{seed_document, seed_entry_counts};
use super::blocklist_format::BlocklistDocument;
use super::feed_cache;

/// Result of an update-db run.
#[derive(Debug, serde::Serialize)]
pub struct UpdateDbResult {
    pub cache_path: String,
    pub total_entries: usize,
    pub python: usize,
    pub npm: usize,
    pub java: usize,
    pub cargo: usize,
    pub sources: Vec<String>,
    pub feeds_ok: Vec<String>,
    pub feeds_failed: Vec<String>,
    pub updated_at: String,
    pub message: String,
}

/// Fetch remote feed URLs (if any), merge with seed, write cache.
///
/// Feed resolution order:
/// 1. Explicit `extra_feeds` (CLI `--feed` / MCP)
/// 2. `PKG_GUARD_FEED_URLS` (comma-separated)
/// 3. Built-in defaults from `data/blocklist/default-feeds.json`
///
/// # Errors
/// Returns an error only if the cache cannot be written after merge.
pub async fn update_db(extra_feeds: &[String]) -> Result<UpdateDbResult> {
    let mut doc = seed_document();
    let mut feeds_ok = vec!["seed".to_string()];
    let mut feeds_failed = Vec::new();

    let mut urls = env_feed_urls();
    for u in extra_feeds {
        if !u.trim().is_empty() && !urls.contains(u) {
            urls.push(u.clone());
        }
    }
    if urls.is_empty() {
        urls = default_feed_urls();
        if !urls.is_empty() {
            info!(
                "Using {} default feed URL(s) from data/blocklist/default-feeds.json",
                urls.len()
            );
        }
    }

    if urls.is_empty() {
        info!("No remote feeds configured; writing seed-only cache");
    } else {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to create HTTP client for update-db")?;

        for url in &urls {
            match fetch_feed(&client, url).await {
                Ok(remote) => {
                    info!("Fetched feed {url} ({} entries)", remote.total_entries());
                    doc.merge(&remote);
                    feeds_ok.push(url.clone());
                }
                Err(e) => {
                    warn!("Feed failed {url}: {e}");
                    feeds_failed.push(format!("{url}: {e}"));
                }
            }
        }
    }

    doc.normalize();
    doc.version = Some(1);
    doc.updated_at = Some(utc_now_iso());
    doc.sources.clone_from(&feeds_ok);
    doc.description = Some(
        "pkg-guard feed cache — merged seed + remote feeds. \
         Custom lists are separate and always take priority."
            .to_string(),
    );

    let path = feed_cache::write_cache(&doc)?;
    let (seed_py, seed_npm, seed_java, seed_cargo) = seed_entry_counts();

    let message = if feeds_failed.is_empty() && urls.is_empty() {
        format!(
            "Wrote seed-only cache ({} packages). Configure PKG_GUARD_FEED_URLS or pass --feed for remote intel.",
            doc.total_entries()
        )
    } else if feeds_failed.is_empty() {
        format!(
            "Updated feed cache with {} packages from {} source(s).",
            doc.total_entries(),
            feeds_ok.len()
        )
    } else if feeds_ok.len() > 1 {
        format!(
            "Updated feed cache with partial success ({} packages). {} feed(s) failed.",
            doc.total_entries(),
            feeds_failed.len()
        )
    } else {
        format!(
            "All remote feeds failed; wrote seed-only cache ({} packages). \
             seed py/npm/java/cargo={seed_py}/{seed_npm}/{seed_java}/{seed_cargo}",
            doc.total_entries()
        )
    };

    Ok(UpdateDbResult {
        cache_path: path.display().to_string(),
        total_entries: doc.total_entries(),
        python: doc.python.len(),
        npm: doc.npm.len(),
        java: doc.java.len(),
        cargo: doc.cargo.len(),
        sources: doc.sources,
        feeds_ok,
        feeds_failed,
        updated_at: doc.updated_at.unwrap_or_default(),
        message,
    })
}

fn env_feed_urls() -> Vec<String> {
    std::env::var("PKG_GUARD_FEED_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Built-in default feeds (embedded). Soft-failed at fetch time if unreachable.
const DEFAULT_FEEDS_JSON: &str = include_str!("../../data/blocklist/default-feeds.json");

#[derive(Debug, serde::Deserialize)]
struct DefaultFeedsFile {
    #[serde(default)]
    feeds: Vec<DefaultFeedEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct DefaultFeedEntry {
    url: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_feed_urls() -> Vec<String> {
    match serde_json::from_str::<DefaultFeedsFile>(DEFAULT_FEEDS_JSON) {
        Ok(file) => file
            .feeds
            .into_iter()
            .filter(|f| f.enabled && !f.url.trim().is_empty())
            .map(|f| f.url)
            .collect(),
        Err(e) => {
            warn!("default-feeds.json invalid: {e}");
            vec![]
        }
    }
}

async fn fetch_feed(client: &reqwest::Client, url: &str) -> Result<BlocklistDocument> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP {}", response.status()));
    }
    let text = response
        .text()
        .await
        .map_err(|e| anyhow!("read body: {e}"))?;
    let mut doc =
        super::blocklist_format::parse_document(&text).map_err(|e| anyhow!("invalid JSON: {e}"))?;
    doc.sources.push(url.to_string());
    doc.normalize();
    Ok(doc)
}

fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Unix timestamp string — file mtime is used for age; this is audit metadata.
    format!("unix:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utc_now_iso_shape() {
        let s = utc_now_iso();
        assert!(s.starts_with("unix:"));
    }
}
