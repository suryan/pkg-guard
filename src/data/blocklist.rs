//! Name blocklist lookup: **custom → feed cache only**.
//!
//! No malicious package list is embedded in the binary. Operators supply:
//! - custom JSON (user/project/env) for zero-day response
//! - feed cache via `pkg-guard update-db` (remote feeds)
//!
//! `popular.json` is still embedded — it is **not** a blocklist; it only
//! drives typosquat similarity against well-known legitimate package names.

use std::sync::LazyLock;

use super::blocklist_format::parse_document;
use super::Ecosystem;

/// Popular packages JSON for typosquat detection (not a denylist).
const POPULAR_JSON: &str = include_str!("../../data/blocklist/popular.json");

static POPULAR_PYTHON: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("python"));
static POPULAR_NPM: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("npm"));
static POPULAR_JAVA: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("java"));
static POPULAR_CARGO: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("cargo"));

fn load_popular(ecosystem: &str) -> Vec<String> {
    let Ok(doc) = parse_document(POPULAR_JSON) else {
        tracing::error!("BUG: embedded popular.json is invalid");
        return vec![];
    };
    match ecosystem {
        "python" => doc.python,
        "npm" => doc.npm,
        "java" => doc.java,
        "cargo" => doc.cargo,
        _ => vec![],
    }
}

/// Where a blocklist hit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistSource {
    /// Not on any blocklist
    None,
    /// User / project / env custom list
    Custom,
    /// Cached remote feed (`pkg-guard update-db`)
    Feed,
}

/// Check if a package is on any blocklist.
#[must_use]
pub fn is_blocklisted(ecosystem: Ecosystem, package_name: &str) -> bool {
    !matches!(
        blocklist_source(ecosystem, package_name),
        BlocklistSource::None
    )
}

/// Report which list matched, if any.
///
/// Order: **custom** → **feed cache**. No embedded seed.
#[must_use]
pub fn blocklist_source(ecosystem: Ecosystem, package_name: &str) -> BlocklistSource {
    if super::custom_blocklist::is_custom_blocklisted(ecosystem, package_name) {
        return BlocklistSource::Custom;
    }
    if super::feed_cache::is_feed_blocklisted(ecosystem, package_name) {
        return BlocklistSource::Feed;
    }
    BlocklistSource::None
}

/// True when neither custom nor feed cache has any entries.
#[must_use]
pub fn name_blocklist_empty() -> bool {
    let custom = super::custom_blocklist::snapshot().total_entries() == 0;
    let feed = super::feed_cache::status_snapshot()
        .get("entries")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        == 0;
    custom && feed
}

/// True when feed cache is missing or older than the configured max age.
#[must_use]
pub fn feed_cache_is_stale() -> bool {
    super::feed_cache::is_stale()
}

/// Popular packages for typosquat detection (legitimate names, not denylist).
#[must_use]
pub fn popular_packages(ecosystem: Ecosystem) -> &'static [String] {
    match ecosystem {
        Ecosystem::Python => POPULAR_PYTHON.as_slice(),
        Ecosystem::Npm => POPULAR_NPM.as_slice(),
        Ecosystem::Java => POPULAR_JAVA.as_slice(),
        Ecosystem::Cargo => POPULAR_CARGO.as_slice(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_popular_python_contains_requests() {
        assert!(popular_packages(Ecosystem::Python)
            .iter()
            .any(|p| p == "requests"));
    }

    #[test]
    fn test_blocklist_source_none_without_lists() {
        // Binary has no seed; without matching custom/feed this must be None.
        // Use a nonsense name unlikely to be in any local custom/feed.
        let src = blocklist_source(Ecosystem::Python, "zz-pkg-guard-no-such-blocklist-entry-zz");
        assert!(matches!(src, BlocklistSource::None));
    }
}
