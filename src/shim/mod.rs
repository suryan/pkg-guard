//! Transparent package-manager shims (multicall).
//!
//! When `pkg-guard` is installed as `pip` / `npm` / `npx` / `uvx` / `cargo`
//! (symlink or copy), it intercepts install-like / package-run commands, runs
//! policy checks, then `exec`s the real tool.
//!
//! **MCP note:** many MCP servers start via `uvx pkg==…` or `npx -y pkg@…`.
//! Those pull the named package **and** transitive deps. Shims gate the
//! top-level package (blocklist + OSV when versioned); they do not fully
//! resolve the dependency tree before exec.
//!
//! ## Known limitations (transparent calls are never perfect)
//! - Bypass via absolute path (`/usr/bin/pip`) or clearing PATH
//! - Incomplete coverage of exotic install forms (git URLs, local paths)
//! - Transitive deps of `uvx`/`npx` are not fully audited before launch
//! - Recursion risk if the "real" binary is not resolved correctly
//! - Container `audit` is **not** run by default (too slow for every install)
//!
//! Mitigations: resolve real binaries by skipping self; env overrides
//! `PKG_GUARD_REAL_<TOOL>`; `PKG_GUARD_SHIM_MODE=off|warn|enforce` (default enforce).

pub(crate) mod cargo;
pub(crate) mod gate;
pub(crate) mod npm;
pub(crate) mod pip;
pub(crate) mod resolve;
pub(crate) mod uvx;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};

use self::resolve::resolve_real_binary;

/// Program names that activate shim mode (matched on `argv[0]` stem).
const WRAPPER_NAMES: &[&str] = &[
    "pip", "pip3", "pip2", "npm", "npx", "yarn", "pnpm", "uvx", "uv", "cargo", "mvn", "gradle",
];

/// Whether this invocation should enter transparent shim mode.
#[must_use]
pub fn is_wrapper_name(program: &str) -> bool {
    let base = program_stem(program);
    WRAPPER_NAMES.contains(&base)
}

/// Stem of a path or program name (`/usr/bin/pip3` → `pip3`).
#[must_use]
pub fn program_stem(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program)
}

/// Run shim for `program` with remaining `args` (without argv0).
///
/// Returns a process exit code (only if exec fails or install is blocked).
pub async fn run(program: &str, args: &[String]) -> Result<i32> {
    let mode = ShimMode::from_env();
    if mode == ShimMode::Off {
        return pass_through(program, args);
    }

    let stem = program_stem(program);
    let plan = match stem {
        "pip" | "pip3" | "pip2" => pip::plan(args),
        "npm" | "npx" | "yarn" | "pnpm" => npm::plan(stem, args),
        "uvx" => uvx::plan_uvx(args),
        "uv" => uvx::plan_uv(args),
        "cargo" => cargo::plan(args),
        // Maven/Gradle: pass through for now (no reliable single-package install parse)
        "mvn" | "gradle" => Plan::PassThrough,
        other => {
            warn!("shim: unknown wrapper '{other}', passing through");
            Plan::PassThrough
        }
    };

    match plan {
        Plan::PassThrough => pass_through(program, args),
        Plan::Gate {
            ecosystem,
            packages,
            files,
            label,
        } => {
            let decision = gate::evaluate(ecosystem, &packages, &files, mode).await?;
            match decision {
                gate::Decision::Allow => pass_through(program, args),
                gate::Decision::Warn(msg) => {
                    eprintln!("pkg-guard shim [{label}]: WARNING — {msg}");
                    pass_through(program, args)
                }
                gate::Decision::Block(msg) => {
                    eprintln!("pkg-guard shim [{label}]: BLOCKED — {msg}");
                    eprintln!("  (set PKG_GUARD_SHIM_MODE=warn to allow with warnings, or =off to disable)");
                    Ok(2)
                }
            }
        }
    }
}

/// What the shim decided to do with this command line.
#[derive(Debug)]
pub enum Plan {
    /// Forward to the real tool with no checks.
    PassThrough,
    /// Run policy, then maybe forward.
    Gate {
        ecosystem: crate::data::Ecosystem,
        packages: Vec<PackageRef>,
        files: Vec<PathBuf>,
        label: String,
    },
}

/// A package name with optional exact version.
#[derive(Debug, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShimMode {
    /// Fully transparent — no checks.
    Off,
    /// Print warnings but always exec the real tool.
    Warn,
    /// Block installs that fail policy (default).
    Enforce,
}

impl ShimMode {
    fn from_env() -> Self {
        match env::var("PKG_GUARD_SHIM_MODE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "off" | "0" | "false" | "disable" | "disabled" => Self::Off,
            "warn" | "warning" | "permissive" => Self::Warn,
            _ => Self::Enforce,
        }
    }
}

fn pass_through(program: &str, args: &[String]) -> Result<i32> {
    let stem = program_stem(program);
    let real = resolve_real_binary(stem)?;
    debug!("shim: exec {} {:?}", real.display(), args);
    exec_real(&real, args, stem)
}

#[cfg(unix)]
fn exec_real(real: &Path, args: &[String], stem: &str) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    // Replaces this process — returns only on failure.
    let err = Command::new(real).args(args).exec();
    Err(anyhow::anyhow!(
        "failed to exec real '{stem}' at {}: {err}",
        real.display()
    ))
}

#[cfg(not(unix))]
fn exec_real(real: &Path, args: &[String], _stem: &str) -> Result<i32> {
    let status = Command::new(real)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {}", real.display()))?;
    Ok(status.code().unwrap_or(1))
}

/// Install symlinks into `dir` for selected tools.
pub fn install_shims(dir: &Path, tools: &[String]) -> Result<Vec<PathBuf>> {
    let self_exe = env::current_exe().context("current_exe")?;
    std::fs::create_dir_all(dir)?;
    let mut created = Vec::new();
    for tool in tools {
        let tool = tool.as_str();
        if !WRAPPER_NAMES.contains(&tool) {
            bail!("unsupported shim name: {tool}");
        }
        let link = dir.join(tool);
        if link.exists() || link.symlink_metadata().is_ok() {
            std::fs::remove_file(&link)
                .with_context(|| format!("remove existing {}", link.display()))?;
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&self_exe, &link)
                .with_context(|| format!("symlink {} -> {}", link.display(), self_exe.display()))?;
        }
        #[cfg(not(unix))]
        {
            // Windows: copy binary (symlinks need privileges)
            std::fs::copy(&self_exe, &link)
                .with_context(|| format!("copy to {}", link.display()))?;
        }
        created.push(link);
    }
    Ok(created)
}

/// Status of shim installation and real-binary resolution.
pub fn status_report(tools: &[&str]) -> serde_json::Value {
    let self_exe = env::current_exe().ok();
    let mut rows = Vec::new();
    for tool in tools {
        let real = resolve_real_binary(tool).ok();
        let env_key = resolve::env_key_for(tool);
        rows.push(serde_json::json!({
            "tool": tool,
            "real_binary": real,
            "env_override": env_key,
            "env_set": env::var(&env_key).ok(),
        }));
    }
    serde_json::json!({
        "pkg_guard_binary": self_exe,
        "shim_mode": format!("{:?}", ShimMode::from_env()).to_ascii_lowercase(),
        "mode_env": "PKG_GUARD_SHIM_MODE=off|warn|enforce",
        "tools": rows,
        "notes": [
            "Install: pkg-guard shim install --dir ~/.local/bin --tools pip,npm,npx,uvx,uv,cargo",
            "Ensure shim dir is before the real tools on PATH",
            "MCP: uvx/npx top-level packages are gated; transitive deps still a residual risk",
            "Bypass risk: calling /usr/bin/uvx or absolute paths skips the gate",
            "Recursion guard: real binary resolution skips this executable",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapper_names() {
        assert!(is_wrapper_name("pip"));
        assert!(is_wrapper_name("/usr/bin/pip3"));
        assert!(is_wrapper_name("npm"));
        assert!(is_wrapper_name("npx"));
        assert!(is_wrapper_name("uvx"));
        assert!(is_wrapper_name("uv"));
        assert!(!is_wrapper_name("pkg-guard"));
        assert!(!is_wrapper_name("check"));
    }

    #[test]
    fn test_program_stem() {
        assert_eq!(program_stem("/usr/bin/pip3"), "pip3");
        assert_eq!(program_stem("cargo"), "cargo");
    }

    #[test]
    #[serial_test::serial]
    fn test_shim_mode_from_env() {
        std::env::set_var("PKG_GUARD_SHIM_MODE", "off");
        assert_eq!(ShimMode::from_env(), ShimMode::Off);
        std::env::set_var("PKG_GUARD_SHIM_MODE", "warn");
        assert_eq!(ShimMode::from_env(), ShimMode::Warn);
        std::env::set_var("PKG_GUARD_SHIM_MODE", "enforce");
        assert_eq!(ShimMode::from_env(), ShimMode::Enforce);
        std::env::set_var("PKG_GUARD_SHIM_MODE", "disabled");
        assert_eq!(ShimMode::from_env(), ShimMode::Off);
        std::env::set_var("PKG_GUARD_SHIM_MODE", "permissive");
        assert_eq!(ShimMode::from_env(), ShimMode::Warn);
        std::env::remove_var("PKG_GUARD_SHIM_MODE");
        assert_eq!(ShimMode::from_env(), ShimMode::Enforce);
    }

    #[test]
    fn test_install_and_status_shims() {
        let dir = std::env::temp_dir().join(format!("pkg-guard-shims-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let created = install_shims(&dir, &["pip".into(), "npm".into()]).expect("install");
        assert_eq!(created.len(), 2);
        assert!(dir.join("pip").exists() || dir.join("pip").symlink_metadata().is_ok());
        // reinstall over existing
        let created2 = install_shims(&dir, &["pip".into()]).expect("reinstall");
        assert_eq!(created2.len(), 1);
        assert!(install_shims(&dir, &["not-a-tool".into()]).is_err());
        let report = status_report(&["pip", "npm", "cargo"]);
        assert_eq!(report["tools"].as_array().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_run_off_mode_and_passthrough_plans() {
        // Never allow exec of a real package manager — always force a missing override.
        std::env::set_var("PKG_GUARD_SHIM_MODE", "off");
        std::env::set_var("PKG_GUARD_REAL_PIP", "/nonexistent/pkg-guard-real-pip-xyz");
        let err = run("pip", &["list".into()]).await;
        assert!(err.is_err());

        std::env::set_var("PKG_GUARD_SHIM_MODE", "enforce");
        std::env::set_var("PKG_GUARD_REAL_MVN", "/nonexistent/mvn-xyz");
        let err = run("mvn", &["--version".into()]).await;
        assert!(err.is_err());
        std::env::remove_var("PKG_GUARD_REAL_MVN");
        std::env::remove_var("PKG_GUARD_REAL_PIP");
        std::env::remove_var("PKG_GUARD_SHIM_MODE");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_run_gate_block_returns_2() {
        let dir = std::env::temp_dir().join(format!("shim-run-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let bl = dir.join("bl.json");
        std::fs::write(
            &bl,
            r#"{"python":["evil-shim-block"],"npm":[],"java":[],"cargo":[]}"#,
        )
        .unwrap();
        std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        // Always override real binary so pass-through cannot replace this process.
        std::env::set_var("PKG_GUARD_REAL_PIP", "/nonexistent/pkg-guard-real-pip-xyz");
        std::env::set_var("PKG_GUARD_SHIM_MODE", "enforce");
        crate::data::custom_blocklist::reload();
        crate::data::feed_cache::reload();

        let code = run("pip", &["install".into(), "evil-shim-block==1.0.0".into()])
            .await
            .unwrap();
        assert_eq!(code, 2);

        // warn mode: still blocked by policy message path, then pass-through fails on missing real pip
        std::env::set_var("PKG_GUARD_SHIM_MODE", "warn");
        let err = run("pip", &["install".into(), "evil-shim-block==1.0.0".into()]).await;
        assert!(err.is_err());

        std::env::remove_var("PKG_GUARD_BLOCKLIST");
        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        std::env::remove_var("PKG_GUARD_SHIM_MODE");
        std::env::remove_var("PKG_GUARD_REAL_PIP");
        crate::data::custom_blocklist::reload();
        crate::data::feed_cache::reload();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
