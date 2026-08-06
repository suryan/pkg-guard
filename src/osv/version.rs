//! Ecosystem-agnostic version comparison for OSV range matching.
//!
//! Not a full semver implementation — good enough for dotted numeric
//! versions common on PyPI/npm/crates/Maven (including pre-release suffixes
//! sorted after the base by string tail).

use std::cmp::Ordering;

/// Compare two version strings. Returns `Ordering` for `a` vs `b`.
#[must_use]
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let pa = split_version(a);
    let pb = split_version(b);
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let sa = pa.get(i).map_or("0", String::as_str);
        let sb = pb.get(i).map_or("0", String::as_str);
        if let (Some(na), Some(nb)) = (parse_num(sa), parse_num(sb)) {
            let c = na.cmp(&nb);
            if c != Ordering::Equal {
                return c;
            }
        } else {
            let c = sa.cmp(sb);
            if c != Ordering::Equal {
                return c;
            }
        }
    }
    Ordering::Equal
}

fn parse_num(s: &str) -> Option<u64> {
    // strip common pre-release markers for the numeric part
    let head = s.split(['-', '+', '_']).next().unwrap_or(s);
    head.parse().ok()
}

fn split_version(v: &str) -> Vec<String> {
    let v = v.trim().trim_start_matches('v').trim_start_matches('V');
    v.split(['.', '-'])
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// True if `version` is in `[introduced, fixed)` or `<= last_affected`.
#[must_use]
pub fn version_matches_range(
    version: &str,
    introduced: &str,
    fixed: Option<&str>,
    last_affected: Option<&str>,
) -> bool {
    // introduced "0" means from the beginning
    if introduced != "0" && cmp_version(version, introduced).is_lt() {
        return false;
    }
    if let Some(fixed) = fixed {
        if !fixed.is_empty() && cmp_version(version, fixed).is_ge() {
            return false;
        }
    }
    if let Some(last) = last_affected {
        if !last.is_empty() && cmp_version(version, last).is_gt() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmp_basic() {
        assert_eq!(cmp_version("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp_version("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(cmp_version("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(cmp_version("1.0", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn test_range() {
        assert!(version_matches_range("1.5.0", "0", Some("2.0.0"), None));
        assert!(!version_matches_range("2.0.0", "0", Some("2.0.0"), None));
        assert!(version_matches_range("1.9.9", "1.0.0", Some("2.0.0"), None));
        assert!(!version_matches_range(
            "0.9.0",
            "1.0.0",
            Some("2.0.0"),
            None
        ));
        assert!(version_matches_range("1.2.3", "0", None, Some("1.2.3")));
        assert!(!version_matches_range("1.2.4", "0", None, Some("1.2.3")));
    }
}
