//! pkg-guard — Package security guardian
//!
//! A single-binary MCP server and CLI tool that audits software packages
//! for supply chain attacks across Python, npm, and Java ecosystems.

mod audit;
mod data;
mod mcp;
mod osv;
mod parsers;
mod project;
mod registry;
mod typosquat;

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();

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
        Commands::UpdateDb { feeds } => {
            let result = data::update_db::update_db(&feeds).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
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
