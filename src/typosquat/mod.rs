//! Typosquat detection engine
//!
//! Detects package names that are suspiciously similar to popular packages
//! using multiple algorithms:
//! - Levenshtein distance (edit distance)
//! - Jaro-Winkler similarity (prefix-weighted)
//! - Homoglyph detection (visual lookalikes: l/1, O/0, I/l)
//! - Common mutation patterns (extra chars, swaps, separator tricks)

use strsim::{jaro_winkler, levenshtein};

use crate::data::blocklist::{blocklist_source, popular_packages, BlocklistSource};
use crate::data::{Ecosystem, TyposquatResult};

/// Homoglyph pairs — characters that look similar in many fonts
const HOMOGLYPHS: &[(char, char)] = &[
    ('l', '1'),
    ('l', 'I'),
    ('O', '0'),
    ('o', '0'),
    ('I', 'l'),
    ('1', 'l'),
    ('0', 'O'),
    ('0', 'o'),
];

/// Minimum Jaro-Winkler similarity to flag as suspicious
const JARO_WINKLER_THRESHOLD: f64 = 0.85;

/// Maximum Levenshtein distance to flag as suspicious
const MAX_LEVENSHTEIN_DISTANCE: usize = 2;

/// Check a package name for typosquatting against known popular packages.
pub fn check_typosquat(ecosystem: Ecosystem, package_name: &str) -> TyposquatResult {
    match blocklist_source(ecosystem, package_name) {
        BlocklistSource::Custom => {
            return TyposquatResult {
                is_suspicious: true,
                is_blocklisted: true,
                blocklist_source: Some("custom".to_string()),
                similar_to: vec![],
                min_levenshtein_distance: None,
                recommendation: "BLOCKED — package is on your custom blocklist \
                     (user/project/env). Remove it from the custom list only if \
                     you intended to allow it."
                    .to_string(),
            };
        }
        BlocklistSource::Builtin => {
            return TyposquatResult {
                is_suspicious: true,
                is_blocklisted: true,
                blocklist_source: Some("builtin".to_string()),
                similar_to: vec![],
                min_levenshtein_distance: None,
                recommendation: "BLOCKED — package is on the built-in malicious blocklist"
                    .to_string(),
            };
        }
        BlocklistSource::None => {}
    }

    let popular = popular_packages(ecosystem);
    let mut similar_packages: Vec<(String, usize, f64)> = Vec::new();

    let pkg_normalized = normalize_name(package_name, ecosystem);

    for &popular_pkg in popular {
        let pop_normalized = normalize_name(popular_pkg, ecosystem);

        // Skip exact matches — that's the real package
        if pkg_normalized == pop_normalized {
            return TyposquatResult {
                is_suspicious: false,
                is_blocklisted: false,
                blocklist_source: None,
                similar_to: vec![],
                min_levenshtein_distance: Some(0),
                recommendation: "OK — this is a known legitimate package".to_string(),
            };
        }

        let lev_distance = levenshtein(&pkg_normalized, &pop_normalized);
        let jw_similarity = jaro_winkler(&pkg_normalized, &pop_normalized);

        let is_similar = lev_distance <= MAX_LEVENSHTEIN_DISTANCE
            || jw_similarity >= JARO_WINKLER_THRESHOLD
            || has_homoglyph_substitution(&pkg_normalized, &pop_normalized)
            || is_separator_trick(package_name, popular_pkg)
            || is_suffix_prefix_trick(package_name, popular_pkg);

        if is_similar {
            similar_packages.push((popular_pkg.to_string(), lev_distance, jw_similarity));
        }
    }

    // Sort by Levenshtein distance (closest first)
    similar_packages.sort_by_key(|(_, dist, _)| *dist);

    let is_suspicious = !similar_packages.is_empty();
    let min_distance = similar_packages.first().map(|(_, d, _)| *d);

    let recommendation = if is_suspicious {
        let closest = &similar_packages[0].0;
        format!(
            "WARNING — package name is suspiciously similar to '{closest}'. \
             Verify this is the intended package before installing.",
        )
    } else {
        "OK — no typosquat patterns detected".to_string()
    };

    TyposquatResult {
        is_suspicious,
        is_blocklisted: false,
        blocklist_source: None,
        similar_to: similar_packages
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect(),
        min_levenshtein_distance: min_distance,
        recommendation,
    }
}

/// Normalize a package name for comparison.
///
/// - Lowercase
/// - For Python/npm: treat hyphens, underscores, and dots as equivalent
/// - For Java: compare only the `artifactId` portion
fn normalize_name(name: &str, ecosystem: Ecosystem) -> String {
    let name = match ecosystem {
        Ecosystem::Java => {
            // For Java packages in groupId:artifactId format, compare artifactId
            name.split(':').next_back().unwrap_or(name)
        }
        Ecosystem::Python | Ecosystem::Npm => name,
    };

    name.to_lowercase().replace(['-', '_', '.'], "")
}

/// Check for homoglyph substitutions (visually similar characters).
fn has_homoglyph_substitution(name: &str, popular: &str) -> bool {
    if name.len() != popular.len() {
        return false;
    }

    let name_chars: Vec<char> = name.chars().collect();
    let pop_chars: Vec<char> = popular.chars().collect();
    let mut differences = 0;
    let mut homoglyph_diffs = 0;

    for (n, p) in name_chars.iter().zip(pop_chars.iter()) {
        if n != p {
            differences += 1;
            if is_homoglyph_pair(*n, *p) {
                homoglyph_diffs += 1;
            }
        }
    }

    // Suspicious if all differences are homoglyphs and there's at least one
    differences > 0 && differences <= 2 && homoglyph_diffs == differences
}

/// Check if two characters are a homoglyph pair.
fn is_homoglyph_pair(a: char, b: char) -> bool {
    for &(h1, h2) in HOMOGLYPHS {
        if (a == h1 && b == h2) || (a == h2 && b == h1) {
            return true;
        }
    }
    false
}

/// Check for separator tricks (adding/removing hyphens, underscores).
///
/// Detects cases where the only difference is extra or different separators
/// that normalization wouldn't catch (e.g., double-hyphens, trailing separators).
fn is_separator_trick(name: &str, popular: &str) -> bool {
    let name_no_sep: String = name
        .chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .collect();
    let pop_no_sep: String = popular
        .chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .collect();

    // Same content but different structure, and originals differ
    name_no_sep.eq_ignore_ascii_case(&pop_no_sep) && name != popular
}

/// Check for common prefix/suffix tricks.
fn is_suffix_prefix_trick(name: &str, popular: &str) -> bool {
    let name_lower = name.to_lowercase();
    let pop_lower = popular.to_lowercase();

    // Common malicious suffixes/prefixes
    let tricks = [
        "-js", "-py", "-python", "-node", "-utils", "-lib", "-core", "js-", "py-", "python-",
        "node-", "get-", "install-",
    ];

    for trick in &tricks {
        // Check if removing the trick from name gives us the popular package
        if let Some(stripped) = name_lower.strip_suffix(trick) {
            if stripped == pop_lower {
                return true;
            }
        }
        if let Some(stripped) = name_lower.strip_prefix(trick) {
            if stripped == pop_lower {
                return true;
            }
        }
    }

    // Check if name is popular + version number suffix
    // e.g., "requests2", "lodash4"
    if name_lower.len() > pop_lower.len()
        && name_lower.starts_with(&pop_lower)
        && name_lower[pop_lower.len()..]
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_is_not_suspicious() {
        let result = check_typosquat(Ecosystem::Python, "requests");
        assert!(!result.is_suspicious);
    }

    #[test]
    fn test_typosquat_detected() {
        let result = check_typosquat(Ecosystem::Python, "requsts");
        assert!(result.is_suspicious);
        assert!(result.similar_to.contains(&"requests".to_string()));
    }

    #[test]
    fn test_blocklisted_package() {
        let result = check_typosquat(Ecosystem::Npm, "crossenv");
        assert!(result.is_suspicious);
        assert!(result.is_blocklisted);
    }

    #[test]
    fn test_unrelated_package_not_flagged() {
        let result = check_typosquat(Ecosystem::Python, "my-custom-internal-lib");
        assert!(!result.is_suspicious);
    }

    #[test]
    fn test_suffix_trick_detected() {
        let result = check_typosquat(Ecosystem::Npm, "express-js");
        assert!(result.is_suspicious);
    }

    #[test]
    fn test_homoglyph_detection() {
        assert!(is_homoglyph_pair('l', '1'));
        assert!(is_homoglyph_pair('O', '0'));
        assert!(!is_homoglyph_pair('a', 'b'));
    }

    #[test]
    fn test_normalize_python() {
        assert_eq!(normalize_name("my-package", Ecosystem::Python), "mypackage");
        assert_eq!(normalize_name("my_package", Ecosystem::Python), "mypackage");
        assert_eq!(normalize_name("My.Package", Ecosystem::Python), "mypackage");
    }

    #[test]
    fn test_normalize_java() {
        assert_eq!(
            normalize_name("org.springframework:spring-core", Ecosystem::Java),
            "springcore"
        );
    }
}
