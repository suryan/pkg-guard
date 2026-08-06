//! Status line formatting for lockfile scan results.

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
        status,
    }
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
