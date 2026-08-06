//! Parse cargo command lines for add/install operations.

use std::path::PathBuf;

use super::{PackageRef, Plan};
use crate::data::Ecosystem;

/// Build a shim plan for `cargo` args.
#[must_use]
pub fn plan(args: &[String]) -> Plan {
    let Some(cmd_idx) = args
        .iter()
        .position(|a| matches!(a.as_str(), "add" | "install"))
    else {
        // Optional: scan lock on build when env set
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "build" | "run" | "test"))
            && std::env::var("PKG_GUARD_SHIM_SCAN_LOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            && PathBuf::from("Cargo.lock").is_file()
        {
            return Plan::Gate {
                ecosystem: Ecosystem::Cargo,
                packages: vec![],
                files: vec![PathBuf::from("Cargo.lock")],
                label: "cargo".to_string(),
            };
        }
        return Plan::PassThrough;
    };

    let mut packages = Vec::new();
    let mut i = cmd_idx + 1;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            if matches!(
                a.as_str(),
                "--vers"
                    | "--version"
                    | "--path"
                    | "--git"
                    | "--branch"
                    | "--tag"
                    | "--rev"
                    | "--registry"
                    | "--features"
                    | "--package"
                    | "-p"
            ) {
                // --vers 1.0 may apply to previous package; simple approach: skip pair
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(pkg) = parse_cargo_spec(a) {
            packages.push(pkg);
        }
        i += 1;
    }

    // cargo add serde --vers 1.0
    if packages.len() == 1 && packages[0].version.is_none() {
        if let Some(v) = find_flag_value(args, &["--vers", "--version"]) {
            packages[0].version = Some(v);
        }
    }

    if packages.is_empty() {
        return Plan::PassThrough;
    }

    Plan::Gate {
        ecosystem: Ecosystem::Cargo,
        packages,
        files: vec![],
        label: "cargo".to_string(),
    }
}

fn find_flag_value(args: &[String], flags: &[&str]) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if flags.contains(&a.as_str()) {
            return args.get(i + 1).cloned();
        }
        for f in flags {
            let prefix = format!("{f}=");
            if let Some(v) = a.strip_prefix(&prefix) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// `serde`, `serde@1.0`, `serde@^1`
fn parse_cargo_spec(spec: &str) -> Option<PackageRef> {
    if spec.starts_with('.') || spec.contains("://") {
        return None;
    }
    if let Some((name, ver)) = spec.split_once('@') {
        if !name.is_empty() {
            // Only treat as exact version if it looks like a version, not a git marker
            let version = if ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                Some(ver.to_string())
            } else {
                None
            };
            return Some(PackageRef {
                name: name.to_string(),
                version,
            });
        }
    }
    Some(PackageRef {
        name: spec.to_string(),
        version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_add() {
        let args = vec!["add".into(), "serde@1.0.200".into()];
        match plan(&args) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "serde");
                assert_eq!(packages[0].version.as_deref(), Some("1.0.200"));
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_cargo_test_passthrough() {
        assert!(matches!(plan(&["test".into()]), Plan::PassThrough));
    }
}
