//! Ecosystem-agnostic version comparison for OSV range matching.
//!
//! Not a full semver implementation — good enough for dotted numeric
//! versions common on PyPI/npm/crates/Maven (including pre-release suffixes
//! sorted after the base by string tail).

use std::cmp::Ordering;

use super::local::IndexedRange;

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

/// Affected versions of one advisory for one package.
#[derive(Debug, Clone, Default)]
pub(crate) struct AffectedSpec {
    pub versions: Vec<String>,
    pub ranges: Vec<IndexedRange>,
}

impl AffectedSpec {
    pub fn affects(&self, version: &str) -> bool {
        self.versions.iter().any(|v| v == version)
            || self.ranges.iter().any(|r| range_contains(r, version))
    }

    /// Smallest version that leaves every range containing `version`.
    /// `None` if any such range has no fix, or only the exact-version list
    /// matched (the list says what is affected, not what is fixed).
    fn next_fix(&self, version: &str) -> Option<String> {
        let mut best: Option<&str> = None;
        let mut any = false;
        for r in self.ranges.iter().filter(|r| range_contains(r, version)) {
            any = true;
            let fixed = r.fixed.as_deref().filter(|f| !f.is_empty())?;
            if best.is_none_or(|b| cmp_version(fixed, b).is_gt()) {
                best = Some(fixed);
            }
        }
        if any {
            best.map(ToString::to_string)
        } else {
            None
        }
    }
}

fn range_contains(r: &IndexedRange, version: &str) -> bool {
    version_matches_range(
        version,
        &r.introduced,
        r.fixed.as_deref(),
        r.last_affected.as_deref(),
    )
}

/// Lowest version above `version` affected by none of `specs`.
///
/// Walks fix-to-fix: a fixed version can itself fall inside another
/// advisory's range, so it is re-checked until clean. `None` when `version`
/// is already clean or some advisory on the path has no known fix.
pub(crate) fn min_clear_version(version: &str, specs: &[&AffectedSpec]) -> Option<String> {
    const MAX_HOPS: usize = 64;
    let mut cur = version.to_string();
    for _ in 0..MAX_HOPS {
        let mut next: Option<String> = None;
        let mut affected = false;
        for spec in specs.iter().filter(|s| s.affects(&cur)) {
            affected = true;
            let fix = spec.next_fix(&cur)?;
            if next.as_deref().is_none_or(|n| cmp_version(&fix, n).is_gt()) {
                next = Some(fix);
            }
        }
        if !affected {
            return (cur != version).then_some(cur);
        }
        let next = next?;
        if cmp_version(&next, &cur).is_le() {
            return None;
        }
        cur = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(ranges: &[(&str, Option<&str>, Option<&str>)], versions: &[&str]) -> AffectedSpec {
        AffectedSpec {
            versions: versions.iter().map(ToString::to_string).collect(),
            ranges: ranges
                .iter()
                .map(|(i, f, l)| IndexedRange {
                    introduced: (*i).into(),
                    fixed: f.map(Into::into),
                    last_affected: l.map(Into::into),
                })
                .collect(),
        }
    }

    #[test]
    fn min_clear_single_and_backport_lines() {
        let s = spec(
            &[("0", Some("1.2.5"), None), ("2.0.0", Some("2.0.3"), None)],
            &[],
        );
        assert_eq!(min_clear_version("1.2.3", &[&s]).as_deref(), Some("1.2.5"));
        assert_eq!(min_clear_version("2.0.1", &[&s]).as_deref(), Some("2.0.3"));
        assert_eq!(min_clear_version("1.9.0", &[&s]), None, "not affected");
    }

    #[test]
    fn min_clear_chains_through_other_advisories() {
        // Fix for A (2.32.0) is still hit by B, whose fix (2.32.4) is hit by C.
        let a = spec(&[("0", Some("2.32.0"), None)], &[]);
        let b = spec(&[("2.30.0", Some("2.32.4"), None)], &[]);
        let c = spec(&[("2.32.3", Some("2.33.0"), None)], &[]);
        assert_eq!(
            min_clear_version("2.31.0", &[&a, &b, &c]).as_deref(),
            Some("2.33.0")
        );
        // Advisory introduced later that the chain lands in, with no fix.
        let d = spec(&[("2.33.0", None, None)], &[]);
        assert_eq!(min_clear_version("2.31.0", &[&a, &b, &c, &d]), None);
    }

    #[test]
    fn min_clear_unfixed_or_list_only_is_none() {
        let unfixed = spec(&[("0", None, Some("1.5.0"))], &[]);
        assert_eq!(min_clear_version("1.0.0", &[&unfixed]), None);
        let mal = spec(&[], &["1.0.1"]);
        assert!(mal.affects("1.0.1"));
        assert_eq!(min_clear_version("1.0.1", &[&mal]), None);
        let empty_fix = spec(&[("0", Some(""), None)], &[]);
        assert_eq!(min_clear_version("1.0.0", &[&empty_fix]), None);
    }

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
