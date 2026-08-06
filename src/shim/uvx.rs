//! Parse `uvx` / `uv tool run` command lines (common MCP launcher path).
//!
//! MCP configs often run:
//!   `uvx mcp-atlassian==0.23.0`
//!   `uvx --from some-pkg cmd`
//!
//! That pulls the named package **and** its transitive deps from `PyPI`.
//! We gate the **named top-level package(s)** (blocklist + OSV when versioned).
//! Full tree resolution is still a gap — prefer pinned versions and local OSV.

use super::{PackageRef, Plan};
use crate::data::Ecosystem;

/// Build a shim plan for `uvx` argv (without program name).
#[must_use]
pub fn plan_uvx(args: &[String]) -> Plan {
    // uvx [global opts] [package-spec] [args to tool...]
    // Flags that take a value
    let value_flags = [
        "--from",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--cache-dir",
        "--index-url",
        "--extra-index-url",
        "--index",
        "--default-index",
        "--find-links",
        "--config-file",
        "--directory",
        "--project",
    ];

    let mut packages = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            break;
        }
        if a.starts_with('-') {
            if value_flags
                .iter()
                .any(|f| a == *f || a.starts_with(&format!("{f}=")))
            {
                if a.contains('=') {
                    // --from=pkg
                    if let Some(v) = a.split_once('=').map(|(_, v)| v) {
                        if let Some(pref) = parse_pep508ish(v) {
                            packages.push(pref);
                        }
                    }
                    i += 1;
                } else if let Some(v) = args.get(i + 1) {
                    if let Some(pref) = parse_pep508ish(v) {
                        // --from / --with often introduce packages
                        if a == "--from" || a == "--with" || a == "--with-editable" {
                            packages.push(pref);
                        }
                    }
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            i += 1;
            continue;
        }

        // First positional is the package / tool to run
        if let Some(pref) = parse_pep508ish(a) {
            packages.push(pref);
        }
        // Remaining args are for the tool — stop scanning
        break;
    }

    if packages.is_empty() {
        return Plan::PassThrough;
    }

    Plan::Gate {
        ecosystem: Ecosystem::Python,
        packages,
        files: vec![],
        label: "uvx".to_string(),
    }
}

/// `uv tool run <pkg>` / `uvx` via `uv` binary.
#[must_use]
pub fn plan_uv(args: &[String]) -> Plan {
    // uv tool run [opts] package [tool-args]
    // uvx is preferred; also catch: uvx as `uv tool run`
    let run_idx = args.iter().position(|a| a == "run");
    let tool_idx = args.iter().position(|a| a == "tool");
    if let (Some(t), Some(r)) = (tool_idx, run_idx) {
        if r == t + 1 {
            return plan_uvx(&args[r + 1..]);
        }
    }
    // `uv pip install ...` — reuse pip-like parsing for install
    if args.iter().any(|a| a == "pip") && args.iter().any(|a| a == "install") {
        return crate::shim::pip::plan(args);
    }
    Plan::PassThrough
}

/// Parse `name`, `name==1.2.3`, `name[extra]==1.0` loosely (uvx specs).
fn parse_pep508ish(spec: &str) -> Option<PackageRef> {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('.') || spec.contains("://") {
        return None;
    }
    // Drop extras: name[foo]
    let base = spec.split('[').next()?.trim();
    if base.is_empty() {
        return None;
    }
    if let Some((name, ver)) = base.split_once("==") {
        let name = name.trim();
        let ver = ver.split(';').next()?.trim();
        if !name.is_empty() && !ver.is_empty() {
            return Some(PackageRef {
                name: name.to_string(),
                version: Some(ver.to_string()),
            });
        }
    }
    // name only (or other operators) — leading identifier
    let name: String = base
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    if name.is_empty() {
        return None;
    }
    Some(PackageRef {
        name,
        version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uvx_pinned_package() {
        match plan_uvx(&["mcp-atlassian==0.23.0".into(), "--help".into()]) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "mcp-atlassian");
                assert_eq!(packages[0].version.as_deref(), Some("0.23.0"));
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_uvx_from_flag() {
        match plan_uvx(&[
            "--from".into(),
            "mcp-grafana==0.1.0".into(),
            "mcp-grafana".into(),
        ]) {
            Plan::Gate { packages, .. } => {
                assert!(packages.iter().any(|p| p.name == "mcp-grafana"));
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_uv_tool_run() {
        match plan_uv(&[
            "tool".into(),
            "run".into(),
            "httpie==3.2.0".into(),
            "http".into(),
            "--help".into(),
        ]) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "httpie");
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_uvx_help_passthrough() {
        assert!(matches!(plan_uvx(&["--help".into()]), Plan::PassThrough));
    }
}
