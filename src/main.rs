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
    }

    Ok(())
}
