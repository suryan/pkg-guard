//! Seed blocklist and lookup across custom → feed cache → built-in seed.
//!
//! Seed data lives in `data/blocklist/seed.json` and is embedded at compile time
//! via `include_str!` (Phase 1). Runtime feed cache is under
//! `~/.cache/pkg-guard/` (Phase 2). User custom lists always win.

use std::sync::LazyLock;

use super::blocklist_format::{parse_document, EcosystemSets};
use super::Ecosystem;

/// Embedded seed blocklist JSON (Phase 1 data file).
const SEED_JSON: &str = include_str!("../../data/blocklist/seed.json");

/// Popular packages JSON for typosquat detection.
const POPULAR_JSON: &str = include_str!("../../data/blocklist/popular.json");

static SEED_SETS: LazyLock<EcosystemSets> = LazyLock::new(load_seed_sets);

static POPULAR_PYTHON: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("python"));
static POPULAR_NPM: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("npm"));
static POPULAR_JAVA: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("java"));
static POPULAR_CARGO: LazyLock<Vec<String>> = LazyLock::new(|| load_popular("cargo"));

/// Seed JSON is generated from repo data files; invalid content is a build bug.
fn load_seed_sets() -> EcosystemSets {
    match parse_document(SEED_JSON) {
        Ok(doc) => doc.to_sets(),
        Err(e) => {
            tracing::error!("BUG: embedded seed.json is invalid: {e}");
            EcosystemSets::default()
        }
    }
}

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

/// Built-in seed as a document (for update-db merge / diagnostics).
#[must_use]
pub fn seed_document() -> super::blocklist_format::BlocklistDocument {
    let mut doc = parse_document(SEED_JSON).unwrap_or_default();
    if !doc.sources.iter().any(|s| s == "seed") {
        doc.sources.push("seed".to_string());
    }
    doc.normalize();
    doc
}

/// Entry counts for the compiled seed: (python, npm, java, cargo).
#[must_use]
pub fn seed_entry_counts() -> (usize, usize, usize, usize) {
    (
        SEED_SETS.python.len(),
        SEED_SETS.npm.len(),
        SEED_SETS.java.len(),
        SEED_SETS.cargo.len(),
    )
}

/// Where a blocklist hit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistSource {
    /// Not on any blocklist
    None,
    /// User / project / env custom list (fast path for brand-new threats)
    Custom,
    /// Cached remote feed (`pkg-guard update-db`)
    Feed,
    /// Compiled-in seed list (`data/blocklist/seed.json`)
    Builtin,
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
/// Order: **custom** → **feed cache** → **built-in seed**.
#[must_use]
pub fn blocklist_source(ecosystem: Ecosystem, package_name: &str) -> BlocklistSource {
    if super::custom_blocklist::is_custom_blocklisted(ecosystem, package_name) {
        return BlocklistSource::Custom;
    }
    if super::feed_cache::is_feed_blocklisted(ecosystem, package_name) {
        return BlocklistSource::Feed;
    }
    if SEED_SETS.contains(ecosystem, package_name) {
        return BlocklistSource::Builtin;
    }
    BlocklistSource::None
}

/// True when feed cache is missing or older than the configured max age.
#[must_use]
pub fn feed_cache_is_stale() -> bool {
    super::feed_cache::is_stale()
}

/// Popular packages for typosquat detection.
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
    fn test_seed_loads_and_blocks_known() {
        assert!(is_blocklisted(Ecosystem::Python, "reqeusts"));
        assert!(is_blocklisted(Ecosystem::Npm, "lodahs"));
        assert!(!is_blocklisted(Ecosystem::Python, "requests"));
    }

    #[test]
    fn test_seed_source_is_builtin_without_custom() {
        // Assuming no custom entry for crossenv
        let src = blocklist_source(Ecosystem::Npm, "crossenv");
        assert!(matches!(
            src,
            BlocklistSource::Builtin | BlocklistSource::Feed
        ));
    }

    #[test]
    fn test_popular_python_contains_requests() {
        assert!(popular_packages(Ecosystem::Python)
            .iter()
            .any(|p| p == "requests"));
    }

    #[test]
    fn test_seed_document_counts() {
        let (py, npm, java, _cargo) = seed_entry_counts();
        assert!(py >= 50);
        assert!(npm >= 50);
        assert!(java >= 1);
    }
}
