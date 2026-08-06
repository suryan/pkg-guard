//! Project-wide dependency and lockfile scanning.
//!
//! Walks a directory tree (respecting common ignore dirs) and runs pin analysis
//! on dependency manifests plus blocklist scans on lock files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use tracing::debug;

use crate::data::{ProjectAuditResult, ProjectFileKind, ProjectFileResult};
use crate::parsers;

/// Directory names skipped while walking a project tree.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
    ".idea",
    ".vscode",
];

/// Maximum depth to walk from the project root.
const MAX_DEPTH: usize = 6;

/// Maximum number of dependency/lock files to process.
const MAX_FILES: usize = 50;

/// Audit an entire project directory for pinning issues and known-malicious packages.
///
/// # Errors
/// Returns an error if the path does not exist or is not a directory.
pub fn audit_project(project_path: &str) -> Result<ProjectAuditResult> {
    let root = Path::new(project_path);
    if !root.exists() {
        return Err(anyhow!("Path not found: {project_path}"));
    }
    if !root.is_dir() {
        return Err(anyhow!("Not a directory: {project_path}"));
    }

    let mut files = Vec::new();
    discover_files(root, 0, &mut files);
    files.sort();
    files.truncate(MAX_FILES);

    let (mut results, files_scanned, total_unpinned, mut total_malicious) =
        analyze_discovered_files(root, &files);
    enrich_requirements_with_blocklist(&mut results, root, &mut total_malicious);

    let status = project_status(files_scanned, total_unpinned, total_malicious);
    let recommendation = project_recommendation(&status, total_unpinned, total_malicious);

    Ok(ProjectAuditResult {
        project_path: root
            .canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .display()
            .to_string(),
        files_scanned,
        total_unpinned,
        total_malicious,
        status,
        recommendation,
        files: results,
    })
}

fn analyze_discovered_files(
    root: &Path,
    files: &[PathBuf],
) -> (Vec<ProjectFileResult>, usize, usize, usize) {
    let mut results = Vec::new();
    let mut total_unpinned = 0usize;
    let mut total_malicious = 0usize;
    let mut files_scanned = 0usize;

    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let path_str = path.display().to_string();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        debug!("Project audit scanning: {path_str}");

        if is_lockfile(filename) {
            files_scanned += 1;
            results.push(scan_one_lockfile(rel, &path_str, &mut total_malicious));
        } else if is_manifest(filename) {
            files_scanned += 1;
            results.push(scan_one_manifest(rel, &path_str, &mut total_unpinned));
        }
    }

    (results, files_scanned, total_unpinned, total_malicious)
}

fn scan_one_lockfile(
    rel: String,
    path_str: &str,
    total_malicious: &mut usize,
) -> ProjectFileResult {
    match parsers::scan_lockfile(path_str) {
        Ok(scan) => {
            *total_malicious += scan.findings_count;
            ProjectFileResult {
                path: rel,
                kind: ProjectFileKind::Lockfile,
                pin: None,
                scan: Some(scan),
                error: None,
            }
        }
        Err(e) => ProjectFileResult {
            path: rel,
            kind: ProjectFileKind::Lockfile,
            pin: None,
            scan: None,
            error: Some(e.to_string()),
        },
    }
}

fn scan_one_manifest(rel: String, path_str: &str, total_unpinned: &mut usize) -> ProjectFileResult {
    match parsers::pin_dependencies(path_str, false, false) {
        Ok(pin) => {
            *total_unpinned += pin.unpinned_count;
            ProjectFileResult {
                path: rel,
                kind: ProjectFileKind::Manifest,
                pin: Some(pin),
                scan: None,
                error: None,
            }
        }
        Err(e) => ProjectFileResult {
            path: rel,
            kind: ProjectFileKind::Manifest,
            pin: None,
            scan: None,
            error: Some(e.to_string()),
        },
    }
}

fn project_status(files_scanned: usize, total_unpinned: usize, total_malicious: usize) -> String {
    if total_malicious > 0 {
        "CRITICAL".to_string()
    } else if total_unpinned > 0 {
        "WARNING".to_string()
    } else if files_scanned == 0 {
        "EMPTY".to_string()
    } else {
        "CLEAN".to_string()
    }
}

fn project_recommendation(status: &str, total_unpinned: usize, total_malicious: usize) -> String {
    match status {
        "CRITICAL" => format!(
            "DO NOT SHIP — {total_malicious} known-malicious package(s) found in lock/dep files"
        ),
        "WARNING" => format!(
            "REVIEW — {total_unpinned} unpinned dependency declaration(s); pin exact versions"
        ),
        "EMPTY" => "No supported dependency or lock files found under this path".to_string(),
        _ => "OK — no malicious packages; dependency pins look solid".to_string(),
    }
}

fn enrich_requirements_with_blocklist(
    results: &mut [ProjectFileResult],
    root: &Path,
    total_malicious: &mut usize,
) {
    for entry in results.iter_mut() {
        if entry.kind != ProjectFileKind::Manifest || entry.scan.is_some() {
            continue;
        }
        let name = Path::new(&entry.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !is_requirements_file(name) {
            continue;
        }
        let path_str = root.join(&entry.path).display().to_string();
        if let Ok(scan) = parsers::scan_lockfile(&path_str) {
            *total_malicious += scan.findings_count;
            entry.scan = Some(scan);
        }
    }
}

fn discover_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        if out.len() >= MAX_FILES {
            break;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.iter().any(|s| *s == name) || name.starts_with('.') {
                continue;
            }
            discover_files(&path, depth + 1, out);
        } else if path.is_file() {
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_manifest(fname) || is_lockfile(fname) {
                out.push(path);
            }
        }
    }
}

fn is_requirements_file(filename: &str) -> bool {
    filename.starts_with("requirements")
        && Path::new(filename)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
}

fn is_manifest(filename: &str) -> bool {
    matches!(
        filename,
        "package.json" | "pom.xml" | "build.gradle" | "build.gradle.kts"
    ) || is_requirements_file(filename)
}

fn is_lockfile(filename: &str) -> bool {
    matches!(
        filename,
        "package-lock.json" | "yarn.lock" | "Pipfile.lock" | "pnpm-lock.yaml"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_is_manifest_and_lockfile() {
        assert!(is_manifest("package.json"));
        assert!(is_manifest("requirements.txt"));
        assert!(is_manifest("requirements-dev.txt"));
        assert!(is_manifest("pom.xml"));
        assert!(!is_manifest("README.md"));
        assert!(is_lockfile("package-lock.json"));
        assert!(is_lockfile("yarn.lock"));
        assert!(!is_lockfile("package.json"));
    }

    #[test]
    fn test_audit_project_empty_dir() {
        let dir = tempfile_dir("pkg-guard-empty");
        let result = audit_project(dir.to_str().expect("utf8")).expect("audit");
        assert_eq!(result.status, "EMPTY");
        assert_eq!(result.files_scanned, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_project_finds_unpinned_and_malicious() {
        let dir = tempfile_dir("pkg-guard-project");
        let req = dir.join("requirements.txt");
        let mut f = fs::File::create(&req).expect("create");
        writeln!(f, "flask").expect("write");
        writeln!(f, "reqeusts==1.0.0").expect("write");

        let result = audit_project(dir.to_str().expect("utf8")).expect("audit");
        assert!(result.files_scanned >= 1);
        assert!(result.total_unpinned >= 1);
        assert!(result.total_malicious >= 1);
        assert_eq!(result.status, "CRITICAL");

        let _ = fs::remove_dir_all(&dir);
    }

    fn tempfile_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{prefix}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("mkdir");
        path
    }
}
