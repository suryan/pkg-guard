//! Dependency file parsers
//!
//! Analyzes dependency files for version pinning compliance and scans
//! lock files against the known-malicious blocklist.
//!
//! Supported formats:
//! - Python: `requirements.txt`, `requirements-*.txt`
//! - npm: `package.json`, `package-lock.json`
//! - Java: `pom.xml`, `build.gradle`

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::data::blocklist::is_blocklisted;
use crate::data::{Ecosystem, MaliciousFinding, PinResult, PinnedDep, ScanResult, UnpinnedDep};

/// Scan a dependency file and report pinning status.
///
/// # Errors
/// Returns an error if the file cannot be read or has an unsupported format.
pub fn pin_dependencies(
    file_path: &str,
    generate_hashes: bool,
    fix_in_place: bool,
) -> Result<PinResult> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(anyhow!("File not found: {file_path}"));
    }

    let content = fs::read_to_string(path)?;
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if is_requirements_file(filename) {
        Ok(parse_requirements(
            &content,
            file_path,
            generate_hashes,
            fix_in_place,
        ))
    } else if filename == "package.json" {
        parse_package_json(&content, file_path, fix_in_place)
    } else if filename == "pom.xml" {
        Ok(parse_pom_xml(&content, file_path))
    } else if filename.eq_ignore_ascii_case("build.gradle")
        || filename.eq_ignore_ascii_case("build.gradle.kts")
    {
        Ok(parse_gradle(&content, file_path))
    } else {
        Err(anyhow!(
            "Unsupported file type: '{filename}'. \
             Supported: requirements*.txt, package.json, pom.xml, build.gradle"
        ))
    }
}

/// Scan a lock file for known malicious packages.
///
/// # Errors
/// Returns an error if the file cannot be read or has an unsupported format.
pub fn scan_lockfile(file_path: &str) -> Result<ScanResult> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(anyhow!("File not found: {file_path}"));
    }

    let content = fs::read_to_string(path)?;
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let findings = if filename == "package-lock.json" {
        scan_npm_lockfile(&content)?
    } else if filename == "yarn.lock" {
        scan_yarn_lockfile(&content)
    } else if is_requirements_file(filename) {
        scan_requirements_as_lockfile(&content)
    } else if filename == "Pipfile.lock" {
        scan_pipfile_lock(&content)?
    } else if filename == "Cargo.lock" {
        scan_cargo_lockfile(&content)
    } else {
        return Err(anyhow!(
            "Unsupported lock file: '{filename}'. \
             Supported: package-lock.json, yarn.lock, requirements.txt, Pipfile.lock, Cargo.lock"
        ));
    };

    Ok(build_scan_result(file_path.to_string(), findings, vec![]))
}

/// Scan a lock file against the blocklist **and** OSV version advisories.
///
/// # Errors
/// Returns an error if the file cannot be read or has an unsupported format.
pub async fn scan_lockfile_with_osv(file_path: &str) -> Result<ScanResult> {
    let mut result = scan_lockfile(file_path)?;
    let packages = extract_resolved_packages(file_path)?;
    // Cap network load for large lockfiles
    let capped: Vec<_> = packages.into_iter().take(80).collect();
    if capped.is_empty() {
        return Ok(result);
    }

    match crate::osv::query_batch(&capped).await {
        Ok(batch) => {
            let mut osv_findings = Vec::new();
            for item in batch {
                for adv in item.advisories {
                    osv_findings.push(adv);
                }
            }
            result.osv_count = osv_findings.len();
            result.osv_findings = osv_findings;
            result.status = compose_scan_status(
                result.findings_count,
                result.osv_count,
                &result.osv_findings,
            );
        }
        Err(e) => {
            result.status = format!(
                "{}; OSV lookup failed: {e}",
                compose_scan_status(result.findings_count, 0, &[])
            );
        }
    }

    Ok(result)
}

fn build_scan_result(
    file: String,
    findings: Vec<MaliciousFinding>,
    osv_findings: Vec<crate::osv::OsvAdvisory>,
) -> ScanResult {
    let findings_count = findings.len();
    let osv_count = osv_findings.len();
    let status = compose_scan_status(findings_count, osv_count, &osv_findings);
    ScanResult {
        file,
        malicious_findings: findings,
        osv_findings,
        findings_count,
        osv_count,
        status,
    }
}

fn compose_scan_status(
    blocklist_count: usize,
    osv_count: usize,
    osv: &[crate::osv::OsvAdvisory],
) -> String {
    let malware = osv.iter().filter(|a| a.is_malware).count();
    if blocklist_count > 0 || malware > 0 {
        format!(
            "CRITICAL — {blocklist_count} blocklist hit(s), {malware} OSV malware, {osv_count} total OSV advisory(ies)"
        )
    } else if osv_count > 0 {
        format!("WARNING — {osv_count} OSV advisory(ies) for resolved versions")
    } else {
        "CLEAN — no known malicious packages or OSV advisories found".to_string()
    }
}

/// Extract (ecosystem, name, version) triples from a lock/requirements file.
fn extract_resolved_packages(file_path: &str) -> Result<Vec<(Ecosystem, String, String)>> {
    let path = Path::new(file_path);
    let content = fs::read_to_string(path)?;
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if filename == "package-lock.json" {
        extract_npm_packages(&content)
    } else if is_requirements_file(filename) {
        Ok(extract_requirements_packages(&content))
    } else if filename == "Pipfile.lock" {
        extract_pipfile_packages(&content)
    } else if filename == "Cargo.lock" {
        Ok(extract_cargo_packages(&content))
    } else {
        // yarn.lock version extraction not implemented yet
        Ok(vec![])
    }
}

fn scan_cargo_lockfile(content: &str) -> Vec<MaliciousFinding> {
    let mut findings = Vec::new();
    for (name, version) in parse_cargo_lock_entries(content) {
        if is_blocklisted(Ecosystem::Cargo, &name) {
            findings.push(MaliciousFinding {
                package: name,
                version: Some(version),
                severity: "CRITICAL".to_string(),
                reason: "Package is on the known-malicious blocklist".to_string(),
            });
        }
    }
    findings
}

fn extract_cargo_packages(content: &str) -> Vec<(Ecosystem, String, String)> {
    parse_cargo_lock_entries(content)
        .into_iter()
        .map(|(n, v)| (Ecosystem::Cargo, n, v))
        .collect()
}

/// Parse `[[package]]` name/version pairs from a Cargo.lock.
fn parse_cargo_lock_entries(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                out.push((n, v));
            }
            in_package = true;
            continue;
        }
        if !in_package {
            continue;
        }
        if trimmed.starts_with('[') && trimmed != "[[package]]" {
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                out.push((n, v));
            }
            in_package = false;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(rest.trim().trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(rest.trim().trim_matches('"').to_string());
        }
    }
    if let (Some(n), Some(v)) = (current_name, current_version) {
        out.push((n, v));
    }
    out
}

fn extract_npm_packages(content: &str) -> Result<Vec<(Ecosystem, String, String)>> {
    let data: Value =
        serde_json::from_str(content).map_err(|e| anyhow!("Invalid JSON in lock file: {e}"))?;
    let mut out = Vec::new();
    if let Some(pkgs) = data.get("packages").and_then(Value::as_object) {
        for (pkg_path, pkg_info) in pkgs {
            let pkg_name = pkg_path.strip_prefix("node_modules/").unwrap_or(pkg_path);
            if pkg_name.is_empty() || pkg_name.contains('/') && !pkg_name.starts_with('@') {
                // skip nested paths like node_modules/a/node_modules/b — only top-level keys
                // actually npm v2 keys are full paths; take basename segment
            }
            let name = if let Some(rest) = pkg_name.strip_prefix("node_modules/") {
                rest
            } else {
                pkg_name
            };
            // For scoped: node_modules/@scope/pkg
            let name = name.rsplit("/node_modules/").next().unwrap_or(name);
            if name.is_empty() {
                continue;
            }
            if let Some(ver) = pkg_info.get("version").and_then(Value::as_str) {
                out.push((Ecosystem::Npm, name.to_string(), ver.to_string()));
            }
        }
    }
    Ok(out)
}

fn extract_requirements_packages(content: &str) -> Vec<(Ecosystem, String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // name==version
        if let Some((name, ver)) = line.split_once("==") {
            let name = name.trim();
            let ver = ver.split(';').next().unwrap_or(ver).trim();
            if !name.is_empty() && !ver.is_empty() {
                out.push((Ecosystem::Python, name.to_string(), ver.to_string()));
            }
        }
    }
    out
}

fn extract_pipfile_packages(content: &str) -> Result<Vec<(Ecosystem, String, String)>> {
    let data: Value =
        serde_json::from_str(content).map_err(|e| anyhow!("Invalid Pipfile.lock: {e}"))?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        if let Some(deps) = data.get(section).and_then(Value::as_object) {
            for (name, info) in deps {
                if let Some(ver) = info.get("version").and_then(Value::as_str) {
                    let ver = ver.trim_start_matches("==").trim();
                    if !ver.is_empty() {
                        out.push((Ecosystem::Python, name.clone(), ver.to_string()));
                    }
                }
            }
        }
    }
    Ok(out)
}

fn is_requirements_file(filename: &str) -> bool {
    filename.starts_with("requirements")
        && std::path::Path::new(filename)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
}

// ─── Python requirements.txt ─────────────────────────────────────────────────

fn parse_requirements(
    content: &str,
    file_path: &str,
    generate_hashes: bool,
    fix_in_place: bool,
) -> PinResult {
    let mut pinned = Vec::new();
    let mut unpinned = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines, comments, options
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Remove inline comments
        let line = line.split('#').next().unwrap_or(line).trim();

        if line.contains("==") {
            let parts: Vec<&str> = line.splitn(2, "==").collect();
            let pkg = parts[0].trim().to_string();
            let version_part = parts.get(1).copied().unwrap_or("").trim();
            let version = version_part
                .split(';')
                .next()
                .unwrap_or(version_part)
                .split('\\')
                .next()
                .unwrap_or(version_part)
                .trim()
                .to_string();
            let has_hash = line.contains("--hash");

            pinned.push(PinnedDep {
                package: pkg,
                version,
                has_hash: Some(has_hash),
                section: None,
            });
        } else if line.contains(">=")
            || line.contains("<=")
            || line.contains("~=")
            || line.contains("!=")
            || line.contains('>')
            || line.contains('<')
        {
            let pkg = line
                .split(&['>', '<', '~', '!', '='][..])
                .next()
                .unwrap_or(line)
                .trim()
                .to_string();
            unpinned.push(UnpinnedDep {
                package: pkg,
                constraint: line.to_string(),
                issue: "uses range specifier instead of exact pin (==)".to_string(),
                section: None,
            });
        } else if !line.contains('=') {
            let pkg = line.split('[').next().unwrap_or(line).trim().to_string();
            unpinned.push(UnpinnedDep {
                package: pkg,
                constraint: line.to_string(),
                issue: "no version specified — must pin with ==".to_string(),
                section: None,
            });
        }
    }

    let total = pinned.len() + unpinned.len();
    let score = format!("{}/{total} pinned", pinned.len());

    let recommendation = if unpinned.is_empty() {
        "All dependencies are properly pinned".to_string()
    } else {
        format!(
            "WARNING: {} dependencies are not pinned to exact versions",
            unpinned.len()
        )
    };

    let fix_suggestion = if fix_in_place && !unpinned.is_empty() {
        if generate_hashes {
            Some(
                "Run: pip-compile --generate-hashes requirements.in > requirements.txt".to_string(),
            )
        } else {
            Some("Run: pip-compile requirements.in > requirements.txt".to_string())
        }
    } else {
        None
    };

    PinResult {
        file: file_path.to_string(),
        total_dependencies: total,
        pinned_count: pinned.len(),
        unpinned_count: unpinned.len(),
        unpinned,
        pinned,
        score,
        recommendation,
        fix_suggestion,
    }
}

// ─── npm package.json ────────────────────────────────────────────────────────

fn parse_package_json(content: &str, file_path: &str, fix_in_place: bool) -> Result<PinResult> {
    let data: Value =
        serde_json::from_str(content).map_err(|e| anyhow!("Invalid JSON in package.json: {e}"))?;

    let mut pinned = Vec::new();
    let mut unpinned = Vec::new();

    let dep_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    for section_name in &dep_sections {
        if let Some(deps) = data.get(*section_name).and_then(Value::as_object) {
            for (pkg, ver_value) in deps {
                let ver = ver_value.as_str().unwrap_or("");
                classify_npm_dep(pkg, ver, section_name, &mut pinned, &mut unpinned);
            }
        }
    }

    let total = pinned.len() + unpinned.len();
    let score = format!("{}/{total} pinned", pinned.len());

    let recommendation = if unpinned.is_empty() {
        "All dependencies are properly pinned".to_string()
    } else {
        format!(
            "WARNING: {} dependencies are not pinned to exact versions",
            unpinned.len()
        )
    };

    let fix_suggestion = if fix_in_place && !unpinned.is_empty() {
        Some(
            "Run: npm shrinkwrap or ensure package-lock.json is committed. \
             Replace ^ and ~ prefixes with exact versions."
                .to_string(),
        )
    } else {
        None
    };

    Ok(PinResult {
        file: file_path.to_string(),
        total_dependencies: total,
        pinned_count: pinned.len(),
        unpinned_count: unpinned.len(),
        unpinned,
        pinned,
        score,
        recommendation,
        fix_suggestion,
    })
}

fn classify_npm_dep(
    pkg: &str,
    ver: &str,
    section_name: &str,
    pinned: &mut Vec<PinnedDep>,
    unpinned: &mut Vec<UnpinnedDep>,
) {
    if ver.starts_with('^') || ver.starts_with('~') {
        unpinned.push(UnpinnedDep {
            package: pkg.to_string(),
            constraint: ver.to_string(),
            issue: format!(
                "uses range specifier '{}' — pin to exact version",
                &ver[..1]
            ),
            section: Some(section_name.to_string()),
        });
    } else if ver == "*" || ver == "latest" || ver.is_empty() {
        unpinned.push(UnpinnedDep {
            package: pkg.to_string(),
            constraint: ver.to_string(),
            issue: "completely unpinned — accepts any version".to_string(),
            section: Some(section_name.to_string()),
        });
    } else if ver.contains("||") || ver.contains(' ') {
        unpinned.push(UnpinnedDep {
            package: pkg.to_string(),
            constraint: ver.to_string(),
            issue: "uses version range expression".to_string(),
            section: Some(section_name.to_string()),
        });
    } else {
        pinned.push(PinnedDep {
            package: pkg.to_string(),
            version: ver.to_string(),
            has_hash: None,
            section: Some(section_name.to_string()),
        });
    }
}

// ─── Maven pom.xml ───────────────────────────────────────────────────────────

fn parse_pom_xml(content: &str, file_path: &str) -> PinResult {
    let mut pinned = Vec::new();
    let mut unpinned = Vec::new();

    let dynamic_patterns = ["LATEST", "RELEASE", "SNAPSHOT", "${"];

    let mut in_dependency = false;
    let mut current_artifact = String::new();
    let mut current_group = String::new();
    let mut current_version = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.contains("<dependency>") {
            in_dependency = true;
            current_artifact.clear();
            current_group.clear();
            current_version.clear();
        } else if trimmed.contains("</dependency>") && in_dependency {
            in_dependency = false;

            if !current_artifact.is_empty() {
                let pkg_name = if current_group.is_empty() {
                    current_artifact.clone()
                } else {
                    format!("{current_group}:{current_artifact}")
                };

                if current_version.is_empty() {
                    unpinned.push(UnpinnedDep {
                        package: pkg_name,
                        constraint: "(no version)".to_string(),
                        issue: "no version specified — may inherit from parent or BOM".to_string(),
                        section: None,
                    });
                } else if dynamic_patterns.iter().any(|p| current_version.contains(p)) {
                    unpinned.push(UnpinnedDep {
                        package: pkg_name,
                        constraint: current_version.clone(),
                        issue: "uses dynamic version — pin to exact release".to_string(),
                        section: None,
                    });
                } else {
                    pinned.push(PinnedDep {
                        package: pkg_name,
                        version: current_version.clone(),
                        has_hash: None,
                        section: None,
                    });
                }
            }
        } else if in_dependency {
            if let Some(val) = extract_xml_value(trimmed, "artifactId") {
                current_artifact = val;
            } else if let Some(val) = extract_xml_value(trimmed, "groupId") {
                current_group = val;
            } else if let Some(val) = extract_xml_value(trimmed, "version") {
                current_version = val;
            }
        }
    }

    let total = pinned.len() + unpinned.len();
    let score = format!("{}/{total} pinned", pinned.len());

    let recommendation = if unpinned.is_empty() {
        "All dependencies are properly pinned".to_string()
    } else {
        format!(
            "WARNING: {} dependencies use dynamic or missing versions",
            unpinned.len()
        )
    };

    PinResult {
        file: file_path.to_string(),
        total_dependencies: total,
        pinned_count: pinned.len(),
        unpinned_count: unpinned.len(),
        unpinned,
        pinned,
        score,
        recommendation,
        fix_suggestion: None,
    }
}

// ─── Gradle build.gradle ─────────────────────────────────────────────────────

fn parse_gradle(content: &str, file_path: &str) -> PinResult {
    let mut pinned = Vec::new();
    let mut unpinned = Vec::new();

    let dep_keywords = [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testRuntimeOnly",
    ];

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }

        for keyword in &dep_keywords {
            if trimmed.starts_with(keyword) {
                if let Some(dep_str) = extract_quoted_string(trimmed) {
                    classify_gradle_dep(dep_str, keyword, &mut pinned, &mut unpinned);
                }
                break;
            }
        }
    }

    let total = pinned.len() + unpinned.len();
    let score = format!("{}/{total} pinned", pinned.len());

    let recommendation = if unpinned.is_empty() {
        "All dependencies are properly pinned".to_string()
    } else {
        format!(
            "WARNING: {} dependencies use dynamic or missing versions",
            unpinned.len()
        )
    };

    PinResult {
        file: file_path.to_string(),
        total_dependencies: total,
        pinned_count: pinned.len(),
        unpinned_count: unpinned.len(),
        unpinned,
        pinned,
        score,
        recommendation,
        fix_suggestion: None,
    }
}

fn classify_gradle_dep(
    dep_str: &str,
    keyword: &str,
    pinned: &mut Vec<PinnedDep>,
    unpinned: &mut Vec<UnpinnedDep>,
) {
    let parts: Vec<&str> = dep_str.split(':').collect();
    if parts.len() >= 3 {
        let pkg = format!("{}:{}", parts[0], parts[1]);
        let version = parts[2].to_string();

        if version.starts_with('$')
            || version.contains('+')
            || version == "latest.release"
            || version == "latest.integration"
        {
            unpinned.push(UnpinnedDep {
                package: pkg,
                constraint: version,
                issue: "uses dynamic version reference".to_string(),
                section: Some(keyword.to_string()),
            });
        } else {
            pinned.push(PinnedDep {
                package: pkg,
                version,
                has_hash: None,
                section: Some(keyword.to_string()),
            });
        }
    } else if parts.len() == 2 {
        unpinned.push(UnpinnedDep {
            package: dep_str.to_string(),
            constraint: "(no version in declaration)".to_string(),
            issue: "no version specified in dependency string".to_string(),
            section: Some(keyword.to_string()),
        });
    }
}

// ─── Lock file scanners ──────────────────────────────────────────────────────

fn scan_npm_lockfile(content: &str) -> Result<Vec<MaliciousFinding>> {
    let data: Value =
        serde_json::from_str(content).map_err(|e| anyhow!("Invalid JSON in lock file: {e}"))?;

    let mut findings = Vec::new();

    let packages = data
        .get("packages")
        .or_else(|| data.get("dependencies"))
        .and_then(Value::as_object);

    if let Some(pkgs) = packages {
        for (pkg_path, pkg_info) in pkgs {
            let pkg_name = pkg_path.strip_prefix("node_modules/").unwrap_or(pkg_path);

            if pkg_name.is_empty() {
                continue;
            }

            if is_blocklisted(Ecosystem::Npm, pkg_name) {
                let version = pkg_info
                    .get("version")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);

                findings.push(MaliciousFinding {
                    package: pkg_name.to_string(),
                    version,
                    severity: "CRITICAL".to_string(),
                    reason: "Package is on the known-malicious blocklist".to_string(),
                });
            }
        }
    }

    Ok(findings)
}

fn scan_yarn_lockfile(content: &str) -> Vec<MaliciousFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') && !trimmed.starts_with('#') && trimmed.contains('@') {
            let without_colon = trimmed.trim_end_matches(':');
            let pkg_name = if without_colon.starts_with('"') {
                without_colon
                    .trim_matches('"')
                    .rsplit_once('@')
                    .map_or(without_colon.trim_matches('"'), |(name, _)| name)
            } else {
                without_colon
                    .rsplit_once('@')
                    .map_or(without_colon, |(name, _)| name)
            };

            if is_blocklisted(Ecosystem::Npm, pkg_name) {
                findings.push(MaliciousFinding {
                    package: pkg_name.to_string(),
                    version: None,
                    severity: "CRITICAL".to_string(),
                    reason: "Package is on the known-malicious blocklist".to_string(),
                });
            }
        }
    }

    findings
}

fn scan_requirements_as_lockfile(content: &str) -> Vec<MaliciousFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        let pkg_name = line
            .split(&['=', '>', '<', '~', '!', '[', ';'][..])
            .next()
            .unwrap_or(line)
            .trim();

        if is_blocklisted(Ecosystem::Python, pkg_name) {
            let version = if line.contains("==") {
                line.split("==")
                    .nth(1)
                    .map(|v| v.split(';').next().unwrap_or(v).trim().to_string())
            } else {
                None
            };

            findings.push(MaliciousFinding {
                package: pkg_name.to_string(),
                version,
                severity: "CRITICAL".to_string(),
                reason: "Package is on the known-malicious blocklist".to_string(),
            });
        }
    }

    findings
}

fn scan_pipfile_lock(content: &str) -> Result<Vec<MaliciousFinding>> {
    let data: Value =
        serde_json::from_str(content).map_err(|e| anyhow!("Invalid JSON in Pipfile.lock: {e}"))?;

    let mut findings = Vec::new();

    for section in &["default", "develop"] {
        if let Some(deps) = data.get(*section).and_then(Value::as_object) {
            for (pkg_name, pkg_info) in deps {
                if is_blocklisted(Ecosystem::Python, pkg_name) {
                    let version = pkg_info
                        .get("version")
                        .and_then(Value::as_str)
                        .map(|s| s.trim_start_matches("==").to_string());

                    findings.push(MaliciousFinding {
                        package: pkg_name.clone(),
                        version,
                        severity: "CRITICAL".to_string(),
                        reason: "Package is on the known-malicious blocklist".to_string(),
                    });
                }
            }
        }
    }

    Ok(findings)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a value from a simple XML element like `<tag>value</tag>`.
fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = line.find(&open)?;
    let end = line.find(&close)?;
    let value_start = start + open.len();
    if value_start < end {
        Some(line[value_start..end].trim().to_string())
    } else {
        None
    }
}

/// Extract a quoted string from a Gradle dependency line.
fn extract_quoted_string(line: &str) -> Option<&str> {
    // Try single quotes first, then double quotes
    if let Some(start) = line.find('\'') {
        if let Some(end) = line[start + 1..].find('\'') {
            return Some(&line[start + 1..start + 1 + end]);
        }
    }
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start + 1..].find('"') {
            return Some(&line[start + 1..start + 1 + end]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirements_pinned() {
        let content = "requests==2.31.0\nflask==3.0.0\n";
        let result = parse_requirements(content, "requirements.txt", false, false);
        assert_eq!(result.pinned_count, 2);
        assert_eq!(result.unpinned_count, 0);
    }

    #[test]
    fn test_parse_requirements_unpinned() {
        let content = "requests>=2.0\nflask\nnumpy~=1.24\n";
        let result = parse_requirements(content, "requirements.txt", false, false);
        assert_eq!(result.unpinned_count, 3);
    }

    #[test]
    fn test_parse_package_json_mixed() {
        let content = r#"{
            "dependencies": {
                "express": "4.18.2",
                "lodash": "^4.17.21"
            },
            "devDependencies": {
                "jest": "~29.7.0"
            }
        }"#;
        let result = parse_package_json(content, "package.json", false).expect("should parse");
        assert_eq!(result.pinned_count, 1);
        assert_eq!(result.unpinned_count, 2);
    }

    #[test]
    fn test_scan_requirements_with_custom_blocklist() {
        let dir = std::env::temp_dir().join(format!("pg-scan-bl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bl = dir.join("bl.json");
        std::fs::write(
            &bl,
            r#"{"python":["reqeusts"],"npm":[],"java":[],"cargo":[]}"#,
        )
        .expect("write");
        std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        crate::data::custom_blocklist::reload();
        crate::data::feed_cache::reload();

        let content = "reqeusts==1.0.0\nflask==3.0.0\n";
        let findings = scan_requirements_as_lockfile(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].package, "reqeusts");

        let clean = "requests==2.31.0\nflask==3.0.0\n";
        assert!(scan_requirements_as_lockfile(clean).is_empty());

        std::env::remove_var("PKG_GUARD_BLOCKLIST");
        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        crate::data::custom_blocklist::reload();
        crate::data::feed_cache::reload();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_cargo_lock_entries() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.40.0"
"#;
        let entries = parse_cargo_lock_entries(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "serde");
        assert_eq!(entries[0].1, "1.0.200");
        assert_eq!(entries[1].0, "tokio");
    }

    #[test]
    fn test_extract_xml_value() {
        assert_eq!(
            extract_xml_value("<artifactId>spring-core</artifactId>", "artifactId"),
            Some("spring-core".to_string())
        );
        assert_eq!(
            extract_xml_value("<version>5.3.20</version>", "version"),
            Some("5.3.20".to_string())
        );
        assert_eq!(extract_xml_value("<other>val</other>", "version"), None);
    }
}
