//! Shared JSON format for seed, feed cache, and custom blocklists.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Common blocklist document shape (seed, feeds, custom files).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlocklistDocument {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// ISO-8601 when this document was last refreshed (feeds/cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Feed URLs or labels that contributed to this document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default)]
    pub python: Vec<String>,
    #[serde(default)]
    pub npm: Vec<String>,
    #[serde(default)]
    pub java: Vec<String>,
}

impl BlocklistDocument {
    /// Merge another document into this one (union of package names).
    pub fn merge(&mut self, other: &Self) {
        for name in &other.python {
            if !self.python.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                self.python.push(name.to_lowercase());
            }
        }
        for name in &other.npm {
            if !self.npm.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                self.npm.push(name.to_lowercase());
            }
        }
        for name in &other.java {
            if !self.java.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                self.java.push(name.to_lowercase());
            }
        }
        for s in &other.sources {
            if !self.sources.contains(s) {
                self.sources.push(s.clone());
            }
        }
    }

    /// Normalize all names to lowercase and dedupe.
    pub fn normalize(&mut self) {
        self.python = dedupe_lower(&self.python);
        self.npm = dedupe_lower(&self.npm);
        self.java = dedupe_lower(&self.java);
    }

    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.python.len() + self.npm.len() + self.java.len()
    }

    #[must_use]
    pub fn to_sets(&self) -> EcosystemSets {
        EcosystemSets {
            python: self.python.iter().map(|s| s.to_lowercase()).collect(),
            npm: self.npm.iter().map(|s| s.to_lowercase()).collect(),
            java: self.java.iter().map(|s| s.to_lowercase()).collect(),
        }
    }
}

/// Per-ecosystem `HashSet`s for fast lookup.
#[derive(Debug, Default, Clone)]
pub struct EcosystemSets {
    pub python: HashSet<String>,
    pub npm: HashSet<String>,
    pub java: HashSet<String>,
}

impl EcosystemSets {
    #[must_use]
    pub fn contains(&self, ecosystem: super::Ecosystem, package_name: &str) -> bool {
        let name = package_name.to_lowercase();
        match ecosystem {
            super::Ecosystem::Python => self.python.contains(&name),
            super::Ecosystem::Npm => self.npm.contains(&name),
            super::Ecosystem::Java => self.java.contains(&name),
        }
    }

    #[must_use]
    pub fn total(&self) -> usize {
        self.python.len() + self.npm.len() + self.java.len()
    }
}

fn dedupe_lower(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let lower = item.to_lowercase();
        if seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    out.sort();
    out
}

/// Parse a blocklist JSON document from a string.
///
/// # Errors
/// Returns an error if JSON is invalid.
pub fn parse_document(text: &str) -> Result<BlocklistDocument, serde_json::Error> {
    serde_json::from_str(text)
}
