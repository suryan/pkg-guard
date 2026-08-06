//! pkg-guard — Package security guardian
//!
//! A single-binary MCP server and CLI tool that audits software packages
//! for supply chain attacks across Python, npm, Java, and Cargo ecosystems.
//!
//! Also supports **transparent package-manager shims**: install as `pip`/`npm`/
//! `cargo` (symlink) to gate installs before exec'ing the real tool.

mod audit;
mod data;
mod mcp;
mod osv;
mod parsers;
mod project;
mod registry;
mod shim;
mod typosquat;

#[cfg(test)]
mod coverage_boost_tests;
#[cfg(test)]
mod extra_coverage_tests;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "pkg-guard",
    version,
    about = "Package security guardian — audits packages for supply chain attacks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP JSON-RPC server over stdio
    Serve,
    /// Audit a single package (standalone CLI mode)
    Audit {
        /// Package ecosystem: python, npm, java
        #[arg(short, long)]
        ecosystem: String,
        /// Package name (for Java use groupId:artifactId)
        #[arg(short, long)]
        package: String,
        /// Exact version to audit
        #[arg(short, long)]
        version: String,
    },
    /// Check a package name for typosquatting
    Check {
        /// Package ecosystem: python, npm, java
        #[arg(short, long)]
        ecosystem: String,
        /// Package name to check
        #[arg(short, long)]
        package: String,
    },
    /// Scan a dependency file for unpinned versions
    Pin {
        /// Path to dependency file
        #[arg(short, long)]
        file: String,
    },
    /// Scan a lock file for known malicious packages
    Scan {
        /// Path to lock file
        #[arg(short, long)]
        file: String,
    },
    /// Audit an entire project tree (manifests + lockfiles)
    Project {
        /// Project root directory (default: current directory)
        #[arg(short, long, default_value = ".")]
        path: String,
    },
    /// Inspect or scaffold custom blocklists (user/project/env)
    Blocklist {
        #[command(subcommand)]
        action: BlocklistCmd,
    },
    /// Refresh feed cache from remote feeds (no embedded denylist in the binary)
    UpdateDb {
        /// Feed URL(s) in blocklist JSON format (repeatable).
        /// Also reads comma-separated `PKG_GUARD_FEED_URLS` and enabled default-feeds.json URLs.
        #[arg(long = "feed")]
        feeds: Vec<String>,
        /// Also download OSV ecosystem dumps and build a local index
        #[arg(long)]
        osv: bool,
    },
    /// Local OSV vulnerability dump (download + offline scan)
    Osv {
        #[command(subcommand)]
        action: OsvCmd,
    },
    /// Manage transparent package-manager shims (multicall)
    Shim {
        #[command(subcommand)]
        action: ShimCmd,
    },
}

#[derive(Subcommand)]
enum OsvCmd {
    /// Download OSV ecosystem dumps and build a local package index
    Update {
        /// Comma-separated ecosystems: python,npm,java,cargo (default: all)
        #[arg(long, short = 'e')]
        ecosystems: Option<String>,
    },
    /// Show local dump status and lookup mode
    Status,
}

#[derive(Subcommand)]
enum ShimCmd {
    /// Create symlinks (pip, npm, cargo, …) pointing at this binary
    Install {
        /// Directory for shims (default: ~/.local/bin)
        #[arg(long, short = 'd')]
        dir: Option<PathBuf>,
        /// Comma-separated tools (default: pip,pip3,npm,npx,cargo)
        #[arg(long, default_value = "pip,pip3,npm,npx,cargo")]
        tools: String,
    },
    /// Show shim mode, real binaries, and env overrides
    Status {
        /// Comma-separated tools to inspect
        #[arg(long, default_value = "pip,pip3,npm,npx,cargo")]
        tools: String,
    },
    /// Remove shim symlinks previously installed
    Uninstall {
        #[arg(long, short = 'd')]
        dir: Option<PathBuf>,
        #[arg(long, default_value = "pip,pip3,npm,npx,cargo")]
        tools: String,
    },
}

#[derive(Subcommand)]
enum BlocklistCmd {
    /// Show candidate paths, loaded files, and entry counts
    Status,
    /// Reload custom blocklists from disk (after editing)
    Reload,
    /// Write an example blocklist.json (default: ~/.config/pkg-guard/blocklist.json)
    Init {
        /// Destination path for the example file
        #[arg(short, long)]
        path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing — logs go to stderr so they don't interfere with MCP stdio
    // Shim mode: quiet by default unless RUST_LOG or PKG_GUARD_SHIM_VERBOSE=1
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else if std::env::var("PKG_GUARD_SHIM_VERBOSE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    // Multicall: if argv[0] is pip/npm/cargo/… run transparent shim instead of clap.
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(prog) = argv.first() {
        let stem = shim::program_stem(prog);
        if shim::is_wrapper_name(stem) {
            let code = shim::run(stem, &argv[1..]).await?;
            std::process::exit(code);
        }
    }

    // Ensure clap sees a stable binary name when invoked via odd paths
    if let Some(first) = argv.first_mut() {
        *first = "pkg-guard".to_string();
    }
    let cli = Cli::parse_from(argv);

    match cli.command {
        Commands::Serve => {
            mcp::server::run_server().await?;
        }
        Commands::Audit {
            ecosystem,
            package,
            version,
        } => {
            let eco = data::Ecosystem::from_str(&ecosystem)?;
            let result = audit::audit_package(eco, &package, &version, true, true, true).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Check { ecosystem, package } => {
            let eco = data::Ecosystem::from_str(&ecosystem)?;
            let result = typosquat::check_typosquat(eco, &package);
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Pin { file } => {
            let result = parsers::pin_dependencies(&file, false, false)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Scan { file } => {
            let result = parsers::scan_lockfile_with_osv(&file).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Project { path } => {
            let result = project::audit_project(&path)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Blocklist { action } => run_blocklist_cmd(action)?,
        Commands::UpdateDb { feeds, osv } => {
            let result = data::update_db::update_db(&feeds).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if osv {
                let osv_result = osv::update_osv(&[]).await?;
                println!("{}", serde_json::to_string_pretty(&osv_result)?);
            }
        }
        Commands::Osv { action } => run_osv_cmd(action).await?,
        Commands::Shim { action } => run_shim_cmd(action)?,
    }

    Ok(())
}

async fn run_osv_cmd(action: OsvCmd) -> anyhow::Result<()> {
    match action {
        OsvCmd::Update { ecosystems } => {
            let ecos = parse_ecosystem_list(ecosystems.as_deref())?;
            let result = osv::update_osv(&ecos).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OsvCmd::Status => {
            println!("{}", serde_json::to_string_pretty(&osv::status_snapshot())?);
        }
    }
    Ok(())
}

fn parse_ecosystem_list(s: Option<&str>) -> anyhow::Result<Vec<data::Ecosystem>> {
    let Some(s) = s else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(data::Ecosystem::from_str(part)?);
    }
    Ok(out)
}

fn run_shim_cmd(action: ShimCmd) -> anyhow::Result<()> {
    match action {
        ShimCmd::Install { dir, tools } => {
            let dir = dir.unwrap_or_else(default_shim_dir);
            let tool_list = parse_tool_list(&tools);
            let created = shim::install_shims(&dir, &tool_list)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "installed": created,
                    "dir": dir,
                    "next_steps": [
                        format!("Ensure {} is early on your PATH", dir.display()),
                        "Optional: export PKG_GUARD_REAL_PIP=$(which -a pip | tail -1)",
                        "Mode: PKG_GUARD_SHIM_MODE=enforce|warn|off",
                        "pkg-guard shim status",
                    ],
                }))?
            );
        }
        ShimCmd::Status { tools } => {
            let tool_list = parse_tool_list(&tools);
            let refs: Vec<&str> = tool_list.iter().map(String::as_str).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&shim::status_report(&refs))?
            );
        }
        ShimCmd::Uninstall { dir, tools } => {
            let dir = dir.unwrap_or_else(default_shim_dir);
            let tool_list = parse_tool_list(&tools);
            let mut removed = Vec::new();
            for tool in &tool_list {
                let link = dir.join(tool);
                if link.symlink_metadata().is_ok() {
                    std::fs::remove_file(&link)?;
                    removed.push(link);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "removed": removed }))?
            );
        }
    }
    Ok(())
}

fn default_shim_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_BIN_HOME") {
        return PathBuf::from(xdg);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/bin")
}

fn parse_tool_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn run_blocklist_cmd(action: BlocklistCmd) -> anyhow::Result<()> {
    match action {
        BlocklistCmd::Status => print_blocklist_status()?,
        BlocklistCmd::Reload => {
            data::custom_blocklist::reload();
            data::feed_cache::reload();
            let snap = data::custom_blocklist::snapshot();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "reloaded": true,
                    "custom_loaded_paths": snap.loaded_paths,
                    "custom_entries": snap.total_entries(),
                    "feed_cache": data::feed_cache::status_snapshot(),
                }))?
            );
        }
        BlocklistCmd::Init { path } => {
            let dest = default_custom_blocklist_path(path);
            if dest.exists() {
                anyhow::bail!(
                    "Refusing to overwrite existing file: {}. Pass a different --path.",
                    dest.display()
                );
            }
            data::custom_blocklist::write_example(&dest)?;
            data::custom_blocklist::reload();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "written": dest,
                    "next_steps": [
                        "Edit the file and add package names under python/npm/java",
                        "Run: pkg-guard blocklist reload",
                        "Verify: pkg-guard check -e python -p <name>"
                    ],
                }))?
            );
        }
    }
    Ok(())
}

fn print_blocklist_status() -> anyhow::Result<()> {
    let snap = data::custom_blocklist::snapshot();
    let status = serde_json::json!({
        "lookup_order": ["custom", "feed_cache"],
        "embedded_blocklist": false,
        "name_blocklist_empty": data::blocklist::name_blocklist_empty(),
        "custom": {
            "candidate_paths": data::custom_blocklist::candidate_paths(),
            "loaded_paths": snap.loaded_paths,
            "total_entries": snap.total_entries(),
            "load_errors": snap.errors,
        },
        "feed_cache": data::feed_cache::status_snapshot(),
        "hints": [
            "No denylist is embedded in the binary",
            "Load names: pkg-guard update-db --feed <url>",
            "Zero-day: pkg-guard blocklist init (custom list)",
            "Custom always wins over feed cache",
            "Optional sample feed file in repo: data/blocklist/example-feed.json (not embedded)",
        ],
    });
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn default_custom_blocklist_path(path: Option<String>) -> std::path::PathBuf {
    if let Some(p) = path {
        return std::path::PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(xdg).join("pkg-guard/blocklist.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".config/pkg-guard/blocklist.json")
}
