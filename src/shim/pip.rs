//! Parse pip command lines for install-like operations.

use std::path::PathBuf;

use super::{PackageRef, Plan};
use crate::data::Ecosystem;

/// Build a shim plan for `pip` / `pip3` args (without program name).
#[must_use]
pub fn plan(args: &[String]) -> Plan {
    // Find global-ish subcommand: pip [global opts] install ...
    let Some(install_idx) = args.iter().position(|a| a == "install") else {
        return Plan::PassThrough;
    };

    let mut packages = Vec::new();
    let mut files = Vec::new();
    let mut i = install_idx + 1;

    while i < args.len() {
        let a = &args[i];
        if a == "-r" || a == "--requirement" {
            if let Some(path) = args.get(i + 1) {
                files.push(PathBuf::from(path));
                i += 2;
                continue;
            }
        }
        if a.starts_with("--requirement=") {
            files.push(PathBuf::from(a.trim_start_matches("--requirement=")));
            i += 1;
            continue;
        }
        // Skip other flags and their values when obvious
        if a.starts_with('-') {
            // flags that take a value
            if matches!(
                a.as_str(),
                "-c" | "--constraint"
                    | "-e"
                    | "--editable"
                    | "-t"
                    | "--target"
                    | "--prefix"
                    | "--root"
                    | "--src"
                    | "-b"
                    | "--build"
                    | "--index-url"
                    | "-i"
                    | "--extra-index-url"
                    | "--find-links"
                    | "-f"
                    | "--proxy"
                    | "--platform"
                    | "--python-version"
                    | "--implementation"
                    | "--abi"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        // Positional requirement / package
        let is_req_file = a.contains("requirements")
            && std::path::Path::new(a)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"));
        if is_req_file {
            files.push(PathBuf::from(a));
        } else if let Some(pref) = parse_requirement(a) {
            packages.push(pref);
        }
        i += 1;
    }

    if packages.is_empty() && files.is_empty() {
        // `pip install` with only flags / local path — pass through
        return Plan::PassThrough;
    }

    Plan::Gate {
        ecosystem: Ecosystem::Python,
        packages,
        files,
        label: "pip".to_string(),
    }
}

/// Parse `name`, `name==1.2.3`, `name>=1`, `name[extra]==1.0` into a [`PackageRef`].
fn parse_requirement(spec: &str) -> Option<PackageRef> {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('.') || spec.starts_with('/') || spec.contains("://") {
        return None; // local / VCS — skip deep parse
    }

    // Drop env markers first: `name==1.0; python_version>="3"`
    let spec = spec.split(';').next()?.trim();

    // Exact pin may appear after extras: `name[extra]==1.2.3`
    if let Some((left, ver)) = spec.split_once("==") {
        let name = strip_extras(left.trim());
        let ver = ver.trim();
        if !name.is_empty() && !ver.is_empty() {
            return Some(PackageRef {
                name,
                version: Some(ver.to_string()),
            });
        }
    }

    // name only (or other operators) — strip extras then take identifier
    let base = strip_extras(spec);
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

/// `name[extra,other]` → `name`
fn strip_extras(spec: &str) -> String {
    spec.split('[').next().unwrap_or(spec).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_install_package() {
        let args = vec!["install".into(), "requests==2.31.0".into()];
        match plan(&args) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "requests");
                assert_eq!(packages[0].version.as_deref(), Some("2.31.0"));
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_pip_install_requirement_file() {
        let args = vec!["install".into(), "-r".into(), "requirements.txt".into()];
        match plan(&args) {
            Plan::Gate {
                files, packages, ..
            } => {
                assert!(packages.is_empty());
                assert_eq!(files.len(), 1);
            }
            Plan::PassThrough => panic!("expected gate"),
        }
    }

    #[test]
    fn test_pip_list_passthrough() {
        let args = vec!["list".into()];
        assert!(matches!(plan(&args), Plan::PassThrough));
    }

    #[test]
    fn test_pip_install_flag_value_pairs_and_extras() {
        match plan(&[
            "install".into(),
            "-i".into(),
            "https://pypi.org/simple".into(),
            "--target".into(),
            "/tmp/t".into(),
            "pkg[extra]==1.2.3".into(),
            "other".into(),
        ]) {
            Plan::Gate { packages, .. } => {
                assert_eq!(packages[0].name, "pkg");
                assert_eq!(packages[0].version.as_deref(), Some("1.2.3"));
                assert_eq!(packages[1].name, "other");
            }
            Plan::PassThrough => panic!("expected gate"),
        }
        // local / vcs skipped
        assert!(matches!(
            plan(&["install".into(), ".".into(), "git+https://x".into()]),
            Plan::PassThrough
        ));
        // bare requirements path as positional
        match plan(&["install".into(), "requirements-dev.txt".into()]) {
            Plan::Gate { files, .. } => assert_eq!(files.len(), 1),
            Plan::PassThrough => panic!("expected gate"),
        }
        assert!(parse_requirement("").is_none());
        assert!(parse_requirement("./local").is_none());
        assert!(parse_requirement("name>=1").is_some());
    }
}
