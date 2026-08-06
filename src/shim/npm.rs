//! Parse npm / yarn / pnpm command lines for install-like operations.

use std::path::PathBuf;

use super::{PackageRef, Plan};
use crate::data::Ecosystem;

/// Build a shim plan for node package managers.
#[must_use]
pub fn plan(tool: &str, args: &[String]) -> Plan {
    let Some(cmd_idx) = args.iter().position(|a| {
        matches!(
            a.as_str(),
            "install" | "i" | "add" | "ci" | "update" | "upgrade"
        )
    }) else {
        return Plan::PassThrough;
    };

    let cmd = args[cmd_idx].as_str();

    // npm ci / yarn install (lockfile) with no package args
    if cmd == "ci" || (cmd == "install" && !has_positional_after(&args[cmd_idx + 1..])) {
        let mut files = Vec::new();
        for name in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"] {
            let p = PathBuf::from(name);
            if p.is_file() {
                files.push(p);
            }
        }
        if files.is_empty() && PathBuf::from("package.json").is_file() {
            files.push(PathBuf::from("package.json"));
        }
        return Plan::Gate {
            ecosystem: Ecosystem::Npm,
            packages: vec![],
            files,
            label: tool.to_string(),
        };
    }

    let mut packages = Vec::new();
    let mut i = cmd_idx + 1;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            // skip flags that take values
            if matches!(
                a.as_str(),
                "--prefix" | "--workspace" | "-w" | "--registry" | "--tag" | "--omit"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(pkg) = parse_npm_spec(a) {
            packages.push(pkg);
        }
        i += 1;
    }

    if packages.is_empty() {
        return Plan::PassThrough;
    }

    Plan::Gate {
        ecosystem: Ecosystem::Npm,
        packages,
        files: vec![],
        label: tool.to_string(),
    }
}

fn has_positional_after(args: &[String]) -> bool {
    args.iter().any(|a| !a.starts_with('-'))
}

/// `lodash`, `lodash@4.17.21`, `@scope/pkg@1.0.0`
fn parse_npm_spec(spec: &str) -> Option<PackageRef> {
    if spec.starts_with('.') || spec.starts_with('/') || spec.contains("://") {
        return None;
    }

    if let Some(rest) = spec.strip_prefix('@') {
        // @scope/name or @scope/name@version
        if let Some((scope_name, ver)) = rest.rsplit_once('@') {
            return Some(PackageRef {
                name: format!("@{scope_name}"),
                version: Some(ver.to_string()),
            });
        }
        return Some(PackageRef {
            name: format!("@{rest}"),
            version: None,
        });
    }

    if let Some((name, ver)) = spec.split_once('@') {
        if !name.is_empty() && !ver.is_empty() {
            return Some(PackageRef {
                name: name.to_string(),
                version: Some(ver.to_string()),
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
    fn test_npm_install_pkg() {
        let args = vec!["install".into(), "lodash@4.17.21".into()];
        match plan("npm", &args) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "lodash");
                assert_eq!(packages[0].version.as_deref(), Some("4.17.21"));
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_npm_test_passthrough() {
        assert!(matches!(plan("npm", &["test".into()]), Plan::PassThrough));
    }

    #[test]
    fn test_npm_flags_scope_and_ci() {
        match plan(
            "npm",
            &[
                "install".into(),
                "--registry".into(),
                "https://registry.npmjs.org".into(),
                "@scope/pkg@2.0.0".into(),
                "plain".into(),
            ],
        ) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "@scope/pkg");
                assert_eq!(packages[0].version.as_deref(), Some("2.0.0"));
                assert_eq!(packages[1].name, "plain");
            }
            Plan::PassThrough => panic!("expected gate"),
        }
        assert!(parse_npm_spec("git+https://x").is_none());
        assert!(parse_npm_spec("@scope/only").is_some());
        // ci without lock in cwd still gates with empty or package.json
        let r = plan("npm", &["ci".into()]);
        assert!(matches!(r, Plan::Gate { .. }));
        let r = plan("pnpm", &["add".into(), "left-pad@1.0.0".into()]);
        assert!(matches!(r, Plan::Gate { .. }));
    }
}
