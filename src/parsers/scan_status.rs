//! Status line formatting for lockfile scan results.

use std::fmt::Write as _;

use crate::data::MaliciousFinding;
use crate::data::ScanResult;

pub(crate) fn build_scan_result(
    file: String,
    findings: Vec<MaliciousFinding>,
    osv_findings: Vec<crate::osv::OsvAdvisory>,
    packages_total: usize,
    packages_osv_checked: usize,
    osv_mode: Option<String>,
    osv_backend: Option<String>,
) -> ScanResult {
    let findings_count = findings.len();
    let osv_count = osv_findings.len();
    let status = compose_scan_status(
        findings_count,
        osv_count,
        &osv_findings,
        packages_total,
        packages_osv_checked,
        osv_backend.as_deref(),
    );
    ScanResult {
        file,
        packages_total,
        packages_blocklist_checked: packages_total,
        packages_osv_checked,
        osv_mode,
        osv_backend,
        malicious_findings: findings,
        osv_findings,
        findings_count,
        osv_count,
        upgrade_suggestions: vec![],
        status,
    }
}

/// Per-package fix advice for results that have advisories.
pub(crate) fn upgrade_suggestions(
    results: &[crate::osv::OsvQueryResult],
) -> Vec<crate::data::UpgradeSuggestion> {
    results
        .iter()
        .filter_map(|r| {
            let advice = r.remediation()?;
            Some(crate::data::UpgradeSuggestion {
                ecosystem: r.ecosystem.clone(),
                package: r.package.clone(),
                current: r.version.clone(),
                recommended: r.recommended_version.clone(),
                advisories: r.advisories.iter().map(|a| a.id.clone()).collect(),
                advice,
            })
        })
        .collect()
}

pub(crate) fn compose_scan_status(
    blocklist_count: usize,
    osv_count: usize,
    osv: &[crate::osv::OsvAdvisory],
    packages_total: usize,
    packages_osv_checked: usize,
    osv_backend: Option<&str>,
) -> String {
    let scope = format_scan_scope(packages_total, packages_osv_checked, osv_backend);
    let malware = osv.iter().filter(|a| a.is_malware).count();
    if blocklist_count > 0 || malware > 0 {
        format!(
            "CRITICAL — {scope}; {blocklist_count} blocklist hit(s), {malware} OSV malware, {osv_count} total OSV advisory(ies)"
        )
    } else if osv_count > 0 {
        format!("WARNING — {scope}; {osv_count} OSV advisory(ies) for resolved versions")
    } else {
        format!("CLEAN — {scope}; no known malicious packages or OSV advisories found")
    }
}

pub(crate) fn format_scan_scope(
    packages_total: usize,
    packages_osv_checked: usize,
    osv_backend: Option<&str>,
) -> String {
    let backend = match osv_backend {
        Some("local") => "OSV=local dump",
        Some("online") => "OSV=online api.osv.dev",
        Some("failed") => "OSV=failed",
        Some("none") => "OSV=skipped",
        Some(other) => other,
        None => "OSV=n/a",
    };
    if packages_total == 0 {
        return format!("scanned 0 packages ({backend})");
    }
    if packages_osv_checked == 0 {
        return format!("scanned {packages_total} package(s) (blocklist only; {backend})");
    }
    format!("scanned {packages_total} package(s), OSV-checked {packages_osv_checked} ({backend})")
}

/// Append "N of M affected package(s) have a fixed version" to the status.
pub(crate) fn append_fix_summary(result: &mut ScanResult) {
    if result.upgrade_suggestions.is_empty() {
        return;
    }
    let fixable = result
        .upgrade_suggestions
        .iter()
        .filter(|u| u.recommended.is_some())
        .count();
    let _ = write!(
        result.status,
        "; {fixable} of {} affected package(s) have a fixed version (see upgrade_suggestions)",
        result.upgrade_suggestions.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::{OsvAdvisory, OsvQueryResult};

    fn result(pkg: &str, ids: &[&str], recommended: Option<&str>) -> OsvQueryResult {
        OsvQueryResult {
            package: pkg.into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            advisories: ids
                .iter()
                .map(|id| OsvAdvisory {
                    id: (*id).into(),
                    summary: String::new(),
                    severity: "HIGH".into(),
                    is_malware: false,
                    package: pkg.into(),
                    version: "1.0.0".into(),
                    ecosystem: "npm".into(),
                    details_url: None,
                    fixed_in: recommended.map(Into::into),
                })
                .collect(),
            recommended_version: recommended.map(Into::into),
            ..OsvQueryResult::default()
        }
    }

    #[test]
    fn suggestions_and_status_summary() {
        let results = [
            result("clean", &[], None),
            result("fixable", &["GHSA-1", "GHSA-2"], Some("1.2.0")),
            result("stuck", &["GHSA-3"], None),
        ];
        let s = upgrade_suggestions(&results);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].package, "fixable");
        assert_eq!(s[0].recommended.as_deref(), Some("1.2.0"));
        assert_eq!(s[0].advisories, ["GHSA-1", "GHSA-2"]);
        assert!(s[1].advice.contains("no fixed version"));

        let mut scan = build_scan_result("x".into(), vec![], vec![], 3, 3, None, None);
        append_fix_summary(&mut scan);
        assert!(!scan.status.contains("upgrade_suggestions"));
        scan.upgrade_suggestions = s;
        append_fix_summary(&mut scan);
        assert!(
            scan.status.ends_with(
                "1 of 2 affected package(s) have a fixed version (see upgrade_suggestions)"
            ),
            "{}",
            scan.status
        );
    }
}
