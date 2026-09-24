//! Policy evaluation for shimmed installs.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use tracing::debug;

use super::transitive::{self, Expansion, LimitHit};
use super::{PackageRef, ShimMode};
use crate::data::Ecosystem;
use crate::osv;
use crate::typosquat;

const OSV_TIMEOUT: Duration = Duration::from_secs(10);
const OSV_CONCURRENCY: usize = 8;

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
    let expanded = expand(ecosystem, packages, blocks, warnings).await;

    let mut osv_items = Vec::new();
    for pkg in &expanded {
        let check = typosquat::check_typosquat(ecosystem, &pkg.name);
        if check.is_blocklisted {
            blocks.push(format!(
                "{} ({})",
                pkg.name,
                check.blocklist_source.as_deref().unwrap_or("blocklist")
            ));
            continue;
        }
        // Typosquat warnings only for top-level packages (noise on deep deps)
        if packages.iter().any(|p| p.name == pkg.name) && check.is_suspicious {
            warnings.push(format!(
                "{} looks like typosquat of {:?}",
                pkg.name, check.similar_to
            ));
        }
        if let Some(ver) = &pkg.version {
            osv_items.push((pkg.name.clone(), ver.clone()));
        }
    }
    check_osv_all(ecosystem, osv_items, OSV_TIMEOUT, blocks, warnings).await;
}

/// What to do when the transitive tree could not be fully verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnIncomplete {
    Warn,
    Block,
}

impl OnIncomplete {
    fn from_env() -> Self {
        match std::env::var("PKG_GUARD_TRANSITIVE_ON_INCOMPLETE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "block" | "deny" | "enforce" => Self::Block,
            _ => Self::Warn,
        }
    }
}

/// Top-level packages plus transitive deps (when enabled). Coverage gaps are
/// pushed as warnings or blocks per `PKG_GUARD_TRANSITIVE_ON_INCOMPLETE`.
async fn expand(
    ecosystem: Ecosystem,
    packages: &[PackageRef],
    blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Vec<PackageRef> {
    if !transitive::transitive_enabled()
        || !matches!(ecosystem, Ecosystem::Python | Ecosystem::Npm)
        || packages.is_empty()
    {
        return packages.to_vec();
    }
    let policy = OnIncomplete::from_env();
    let sink = match policy {
        OnIncomplete::Warn => warnings,
        OnIncomplete::Block => blocks,
    };
    match transitive::expand_with_transitive(ecosystem, packages).await {
        Ok(exp) => {
            if exp.packages.len() > packages.len() {
                eprintln!(
                    "pkg-guard shim: expanded {} top-level package(s) → {} with transitive deps ({} without exact version: name checks only)",
                    packages.len(),
                    exp.packages.len(),
                    exp.unversioned
                );
            }
            if !exp.is_complete() {
                sink.push(incomplete_message(&exp));
            }
            exp.packages
        }
        Err(e) => {
            sink.push(format!("transitive audit unavailable: {e}"));
            packages.to_vec()
        }
    }
}

fn incomplete_message(exp: &Expansion) -> String {
    const SHOWN: usize = 5;
    let mut parts = Vec::new();
    if !exp.unresolved.is_empty() {
        let mut list = exp.unresolved[..exp.unresolved.len().min(SHOWN)].join(", ");
        if exp.unresolved.len() > SHOWN {
            let _ = write!(list, ", +{} more", exp.unresolved.len() - SHOWN);
        }
        parts.push(format!("{} unresolved ({list})", exp.unresolved.len()));
    }
    if let Some(limit) = exp.limit_hit {
        let which = match limit {
            LimitHit::Budget => "time budget PKG_GUARD_TRANSITIVE_BUDGET_MS",
            LimitHit::MaxNodes => "node cap PKG_GUARD_TRANSITIVE_MAX_NODES",
            LimitHit::MaxDepth => "depth cap PKG_GUARD_TRANSITIVE_MAX_DEPTH",
        };
        parts.push(format!(
            "stopped at {which} with {} node(s) not expanded",
            exp.unexpanded
        ));
    }
    format!(
        "transitive audit incomplete, deps below these were NOT checked: {}",
        parts.join("; ")
    )
}

/// Query OSV for all versioned packages concurrently, bounded by `timeout`.
async fn check_osv_all(
    ecosystem: Ecosystem,
    items: Vec<(String, String)>,
    timeout: Duration,
    blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let total = items.len();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut results = futures_util::stream::iter(items)
        .map(|(name, ver)| async move {
            let r = osv::query_package(ecosystem, &name, &ver).await;
            (name, ver, r)
        })
        .buffer_unordered(OSV_CONCURRENCY);
    let mut done = 0usize;
    let mut failures: Vec<String> = Vec::new();
    while let Ok(Some((name, ver, r))) = tokio::time::timeout_at(deadline, results.next()).await {
        done += 1;
        match r {
            Ok(res) => apply_osv(&name, &ver, &res, blocks, warnings),
            Err(e) => failures.push(format!("{name}@{ver}: {e}")),
        }
    }
    if !failures.is_empty() {
        warnings.push(format!(
            "OSV lookup failed for {} package(s) (first: {})",
            failures.len(),
            failures[0]
        ));
    }
    if done < total {
        warnings.push(format!(
            "OSV lookup timed out after {}s; {} of {total} package version(s) not checked",
            timeout.as_secs(),
            total - done
        ));
    }
}

fn apply_osv(
    name: &str,
    ver: &str,
    osv_result: &osv::OsvQueryResult,
    blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let fix = osv_result
        .remediation()
        .map_or(String::new(), |r| format!(" ({r})"));
    if osv_result.has_malware() {
        let ids: Vec<_> = osv_result
            .advisories
            .iter()
            .filter(|a| a.is_malware)
            .map(|a| a.id.as_str())
            .collect();
        blocks.push(format!("{name}@{ver} OSV malware {}{fix}", ids.join(",")));
    } else if osv_result.has_critical_or_high() {
        let ids: Vec<_> = osv_result
            .advisories
            .iter()
            .filter(|a| matches!(a.severity.as_str(), "CRITICAL" | "HIGH") || a.is_malware)
            .map(|a| a.id.as_str())
            .collect();
        blocks.push(format!(
            "{name}@{ver} OSV high/critical {}{fix}",
            ids.join(",")
        ));
    } else if !osv_result.advisories.is_empty() {
        warnings.push(format!(
            "{name}@{ver} has {} OSV advisory(ies){fix}",
            osv_result.advisories.len()
        ));
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

    #[tokio::test]
    #[serial_test::serial]
    async fn test_evaluate_with_transitive_expand() {
        std::env::set_var("PKG_GUARD_SHIM_TRANSITIVE", "1");
        std::env::set_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS", "0");
        // requests has several runtime deps — exercises expand + OSV on tree
        let d = evaluate(
            Ecosystem::Python,
            &[PackageRef {
                name: "requests".into(),
                version: Some("2.31.0".into()),
            }],
            &[],
            ShimMode::Warn,
        )
        .await
        .unwrap();
        assert!(matches!(d, Decision::Allow | Decision::Warn(_)));

        let d2 = evaluate(
            Ecosystem::Npm,
            &[PackageRef {
                name: "left-pad".into(),
                version: Some("1.3.0".into()),
            }],
            &[],
            ShimMode::Warn,
        )
        .await
        .unwrap();
        assert!(matches!(d2, Decision::Allow | Decision::Warn(_)));
        std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
        std::env::remove_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_incomplete_transitive_warns_or_blocks_per_policy() {
        use crate::shim::transitive::tests::{route, serve, Routes};
        let mut r = Routes::new();
        route(
            &mut r,
            "/pg-gate-root/latest",
            r#"{"version":"1.0.0","dependencies":{"pg-gate-missing":"^1.0.0"}}"#,
        );
        let mock = serve(r).await;
        std::env::set_var("PKG_GUARD_NPM_REGISTRY", &mock.base);
        std::env::set_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS", "0");
        std::env::set_var("PKG_GUARD_OSV_MODE", "local");
        std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
        let pkgs = [PackageRef {
            name: "pg-gate-root".into(),
            version: None,
        }];

        std::env::remove_var("PKG_GUARD_TRANSITIVE_ON_INCOMPLETE");
        let d = evaluate(Ecosystem::Npm, &pkgs, &[], ShimMode::Enforce)
            .await
            .unwrap();
        let Decision::Warn(msg) = d else {
            panic!("expected warn, got {d:?}")
        };
        assert!(msg.contains("pg-gate-missing: 404"), "{msg}");

        std::env::set_var("PKG_GUARD_TRANSITIVE_ON_INCOMPLETE", "block");
        let d = evaluate(Ecosystem::Npm, &pkgs, &[], ShimMode::Enforce)
            .await
            .unwrap();
        assert!(
            matches!(d, Decision::Block(ref m) if m.contains("NOT checked")),
            "{d:?}"
        );
        let d = evaluate(Ecosystem::Npm, &pkgs, &[], ShimMode::Warn)
            .await
            .unwrap();
        assert!(matches!(d, Decision::Warn(_)), "warn mode never blocks");

        for k in [
            "PKG_GUARD_NPM_REGISTRY",
            "PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS",
            "PKG_GUARD_OSV_MODE",
            "PKG_GUARD_TRANSITIVE_ON_INCOMPLETE",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn test_apply_osv_includes_remediation() {
        let adv = |id: &str, severity: &str| osv::OsvAdvisory {
            id: id.into(),
            summary: String::new(),
            severity: severity.into(),
            is_malware: id.starts_with("MAL-"),
            package: "p".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            details_url: None,
            fixed_in: None,
        };
        let res = |advisories, rec: Option<&str>| osv::OsvQueryResult {
            package: "p".into(),
            version: "1.0.0".into(),
            advisories,
            recommended_version: rec.map(Into::into),
            ..osv::OsvQueryResult::default()
        };
        let (mut blocks, mut warnings) = (Vec::new(), Vec::new());
        apply_osv(
            "p",
            "1.0.0",
            &res(vec![adv("GHSA-h", "HIGH")], Some("1.4.2")),
            &mut blocks,
            &mut warnings,
        );
        apply_osv(
            "p",
            "1.0.0",
            &res(vec![adv("MAL-1", "CRITICAL")], None),
            &mut blocks,
            &mut warnings,
        );
        apply_osv(
            "p",
            "1.0.0",
            &res(vec![adv("GHSA-l", "LOW")], Some("1.0.1")),
            &mut blocks,
            &mut warnings,
        );
        assert!(
            blocks[0].ends_with(
                "GHSA-h (upgrade p to 1.4.2, the lowest version with no known advisories)"
            ),
            "{blocks:?}"
        );
        assert!(
            blocks[1].contains("(remove p@1.0.0: malicious"),
            "{blocks:?}"
        );
        assert!(warnings[0].contains("upgrade p to 1.0.1"), "{warnings:?}");
    }

    #[test]
    fn test_incomplete_message_lists_gaps() {
        let exp = Expansion {
            unresolved: (0..7).map(|i| format!("p{i}: 404")).collect(),
            unexpanded: 12,
            limit_hit: Some(LimitHit::Budget),
            ..Expansion::default()
        };
        let m = incomplete_message(&exp);
        assert!(m.contains("7 unresolved (p0: 404"), "{m}");
        assert!(m.contains("+2 more"), "{m}");
        assert!(
            m.contains("PKG_GUARD_TRANSITIVE_BUDGET_MS with 12 node(s)"),
            "{m}"
        );
        for (limit, knob) in [
            (LimitHit::MaxNodes, "MAX_NODES"),
            (LimitHit::MaxDepth, "MAX_DEPTH"),
        ] {
            let exp = Expansion {
                limit_hit: Some(limit),
                ..Expansion::default()
            };
            assert!(incomplete_message(&exp).contains(knob));
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_osv_timeout_and_failures_are_reported() {
        std::env::set_var("PKG_GUARD_OSV_MODE", "online");
        let (mut blocks, mut warnings) = (Vec::new(), Vec::new());
        let items = vec![("six".to_string(), "1.16.0".to_string())];
        check_osv_all(
            Ecosystem::Python,
            items,
            Duration::ZERO,
            &mut blocks,
            &mut warnings,
        )
        .await;
        assert!(
            warnings.iter().any(|w| w.contains("timed out")),
            "{warnings:?}"
        );

        let dir = std::env::temp_dir().join(format!("gate-osv-empty-{}", std::process::id()));
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        std::env::set_var("PKG_GUARD_OSV_MODE", "local");
        warnings.clear();
        // No test builds a Maven index, so the local lookup always fails.
        check_osv_all(
            Ecosystem::Java,
            vec![("g:a".to_string(), "1".to_string())],
            OSV_TIMEOUT,
            &mut blocks,
            &mut warnings,
        )
        .await;
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("OSV lookup failed for 1")),
            "{warnings:?}"
        );
        std::env::remove_var("PKG_GUARD_OSV_MODE");
        std::env::remove_var("PKG_GUARD_CACHE_DIR");
    }
}
