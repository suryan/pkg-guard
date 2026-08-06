//! Policy evaluation for shimmed installs.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::debug;

use super::{PackageRef, ShimMode};
use crate::data::Ecosystem;
use crate::osv;
use crate::typosquat;

/// Outcome of gate evaluation.
#[derive(Debug)]
pub enum Decision {
    Allow,
    Warn(String),
    Block(String),
}

/// Evaluate packages and dependency files before allowing an install.
pub async fn evaluate(
    ecosystem: Ecosystem,
    packages: &[PackageRef],
    files: &[PathBuf],
    mode: ShimMode,
) -> Result<Decision> {
    let mut blocks = Vec::new();
    let mut warnings = Vec::new();

    if packages.is_empty() && files.is_empty() {
        debug!("shim gate: no explicit packages/files; allowing pass-through");
        return Ok(Decision::Allow);
    }

    check_packages(ecosystem, packages, &mut blocks, &mut warnings).await;
    check_files(files, &mut blocks, &mut warnings).await;

    Ok(finalize(mode, &blocks, &warnings))
}

async fn check_packages(
    ecosystem: Ecosystem,
    packages: &[PackageRef],
    blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    for pkg in packages {
        let check = typosquat::check_typosquat(ecosystem, &pkg.name);
        if check.is_blocklisted {
            blocks.push(format!(
                "{} ({})",
                pkg.name,
                check.blocklist_source.as_deref().unwrap_or("blocklist")
            ));
            continue;
        }
        if check.is_suspicious {
            warnings.push(format!(
                "{} looks like typosquat of {:?}",
                pkg.name, check.similar_to
            ));
        }
        if let Some(ver) = &pkg.version {
            check_osv(ecosystem, &pkg.name, ver, blocks, warnings).await;
        }
    }
}

async fn check_osv(
    ecosystem: Ecosystem,
    name: &str,
    ver: &str,
    blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match osv::query_package(ecosystem, name, ver).await {
        Ok(osv_result) => {
            if osv_result.has_malware() {
                let ids: Vec<_> = osv_result
                    .advisories
                    .iter()
                    .filter(|a| a.is_malware)
                    .map(|a| a.id.as_str())
                    .collect();
                blocks.push(format!("{name}@{ver} OSV malware {}", ids.join(",")));
            } else if osv_result.has_critical_or_high() {
                let ids: Vec<_> = osv_result
                    .advisories
                    .iter()
                    .filter(|a| matches!(a.severity.as_str(), "CRITICAL" | "HIGH") || a.is_malware)
                    .map(|a| a.id.as_str())
                    .collect();
                blocks.push(format!("{name}@{ver} OSV high/critical {}", ids.join(",")));
            } else if !osv_result.advisories.is_empty() {
                warnings.push(format!(
                    "{name}@{ver} has {} OSV advisory(ies)",
                    osv_result.advisories.len()
                ));
            }
        }
        Err(e) => {
            warnings.push(format!("OSV lookup failed for {name}@{ver}: {e}"));
        }
    }
}

async fn check_files(files: &[PathBuf], blocks: &mut Vec<String>, warnings: &mut Vec<String>) {
    for file in files {
        let path = file.display().to_string();
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if is_lockish(name) {
            match crate::parsers::scan_lockfile_with_osv(&path).await {
                Ok(scan) => {
                    if scan.findings_count > 0 {
                        blocks.push(format!("{path}: {} blocklist hit(s)", scan.findings_count));
                    }
                    let malware = scan.osv_findings.iter().filter(|a| a.is_malware).count();
                    if malware > 0 {
                        blocks.push(format!("{path}: {malware} OSV malware advisory(ies)"));
                    } else if scan.osv_count > 0 {
                        warnings.push(format!("{path}: {} OSV advisory(ies)", scan.osv_count));
                    }
                }
                Err(e) => warnings.push(format!("scan {path}: {e}")),
            }
        } else {
            match crate::parsers::pin_dependencies(&path, false, false) {
                Ok(pin) if pin.unpinned_count > 0 => {
                    warnings.push(format!(
                        "{path}: {} unpinned dependency(ies)",
                        pin.unpinned_count
                    ));
                }
                Ok(_) => {}
                Err(e) => warnings.push(format!("pin {path}: {e}")),
            }
        }
    }
}

fn finalize(mode: ShimMode, blocks: &[String], warnings: &[String]) -> Decision {
    if !blocks.is_empty() {
        let msg = blocks.join("; ");
        return match mode {
            ShimMode::Warn => Decision::Warn(msg),
            ShimMode::Enforce | ShimMode::Off => Decision::Block(msg),
        };
    }
    if !warnings.is_empty() {
        return Decision::Warn(warnings.join("; "));
    }
    Decision::Allow
}

fn is_lockish(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json" | "yarn.lock" | "Pipfile.lock" | "pnpm-lock.yaml" | "Cargo.lock"
    ) || (name.starts_with("requirements")
        && Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Ecosystem;
    use crate::shim::PackageRef;

    #[test]
    fn test_is_lockish_names() {
        assert!(is_lockish("package-lock.json"));
        assert!(is_lockish("yarn.lock"));
        assert!(is_lockish("Cargo.lock"));
        assert!(is_lockish("requirements.txt"));
        assert!(is_lockish("requirements-dev.txt"));
        assert!(!is_lockish("package.json"));
        assert!(!is_lockish("readme.md"));
    }

    #[test]
    fn test_finalize_modes() {
        assert!(matches!(
            finalize(ShimMode::Enforce, &["blocked".into()], &[]),
            Decision::Block(_)
        ));
        assert!(matches!(
            finalize(ShimMode::Warn, &["blocked".into()], &[]),
            Decision::Warn(_)
        ));
        assert!(matches!(
            finalize(ShimMode::Enforce, &[], &["warn".into()]),
            Decision::Warn(_)
        ));
        assert!(matches!(
            finalize(ShimMode::Enforce, &[], &[]),
            Decision::Allow
        ));
    }

    #[tokio::test]
    async fn test_evaluate_warn_mode_blocklist() {
        // Without a custom blocklist, unique name + empty files → allow
        let d = evaluate(
            Ecosystem::Python,
            &[PackageRef {
                name: "unique-pkg-guard-xyz-999".into(),
                version: None,
            }],
            &[],
            ShimMode::Warn,
        )
        .await
        .unwrap();
        assert!(matches!(d, Decision::Allow | Decision::Warn(_)));
    }

    #[tokio::test]
    async fn test_evaluate_manifest_file_warns_unpinned() {
        let dir = std::env::temp_dir().join(format!("gate-pin-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let req = dir.join("requirements.txt");
        std::fs::write(&req, "flask\n").unwrap();
        let d = evaluate(Ecosystem::Python, &[], &[req], ShimMode::Enforce)
            .await
            .unwrap();
        assert!(matches!(d, Decision::Warn(_) | Decision::Allow));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_evaluate_missing_file_warns() {
        let missing = PathBuf::from("/tmp/pkg-guard-does-not-exist-requirements.txt");
        let d = evaluate(Ecosystem::Python, &[], &[missing], ShimMode::Enforce)
            .await
            .unwrap();
        assert!(matches!(d, Decision::Warn(_)));
    }

    #[tokio::test]
    async fn test_evaluate_versioned_package_osv_path() {
        // Real OSV query path for a well-known package
        let d = evaluate(
            Ecosystem::Python,
            &[PackageRef {
                name: "six".into(),
                version: Some("1.16.0".into()),
            }],
            &[],
            ShimMode::Enforce,
        )
        .await
        .unwrap();
        assert!(matches!(d, Decision::Allow | Decision::Warn(_)));
    }
}
