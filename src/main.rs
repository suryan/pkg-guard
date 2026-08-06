//! pkg-guard — Package security guardian
//!
//! A single-binary MCP server and CLI tool that audits software packages
//! for supply chain attacks across Python, npm, and Java ecosystems.

mod audit;
mod data;
mod mcp;
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
            let result = parsers::scan_lockfile(&file)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Project { path } => {
            let result = project::audit_project(&path)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Blocklist { action } => match action {
            BlocklistCmd::Status => {
                let snap = data::custom_blocklist::snapshot();
                let candidates = data::custom_blocklist::candidate_paths();
                let status = serde_json::json!({
                    "candidate_paths": candidates,
                    "loaded_paths": snap.loaded_paths,
                    "total_custom_entries": snap.total_entries(),
                    "load_errors": snap.errors,
                    "hint": "Edit a custom JSON blocklist, then run: pkg-guard blocklist reload",
                });
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            BlocklistCmd::Reload => {
                data::custom_blocklist::reload();
                let snap = data::custom_blocklist::snapshot();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "reloaded": true,
                        "loaded_paths": snap.loaded_paths,
                        "total_custom_entries": snap.total_entries(),
                        "load_errors": snap.errors,
                    }))?
                );
            }
            BlocklistCmd::Init { path } => {
                let dest = if let Some(p) = path {
                    std::path::PathBuf::from(p)
                } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
                    std::path::PathBuf::from(xdg).join("pkg-guard/blocklist.json")
                } else {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    std::path::PathBuf::from(home).join(".config/pkg-guard/blocklist.json")
                };
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
                            "Run: pkg-guard blocklist reload  (or restart MCP serve)",
                            "Verify: pkg-guard check -e python -p <name>"
                        ],
                    }))?
                );
            }
        },
    }

    Ok(())
}
