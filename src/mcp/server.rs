//! MCP JSON-RPC server — reads from stdin, writes to stdout

use anyhow::Result;
use serde_json::{Map, Value};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

use super::protocol::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo,
    ToolCallResult, ToolsCapability, ToolsListResult,
};
use super::tools::get_tool_definitions;
use crate::{audit, data, parsers, project, registry, typosquat};

const SERVER_NAME: &str = "pkg-guard";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the MCP server, reading JSON-RPC from stdin and writing responses to stdout.
///
/// # Errors
/// Returns an error if I/O operations fail.
pub async fn run_server() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    debug!("pkg-guard MCP server starting");

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                warn!("Failed to parse JSON-RPC request: {e}");
                continue;
            }
        };

        debug!("Received method: {}", request.method);

        // Notifications (no id) don't get responses
        if request.id.is_none() || request.method.starts_with("notifications/") {
            continue;
        }

        let response = handle_request(&request).await;

        let response_json = serde_json::to_string(&response)?;
        stdout.write_all(response_json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }

    debug!("pkg-guard MCP server shutting down");
    Ok(())
}

async fn handle_request(request: &JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => {
            let result = InitializeResult {
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: ServerCapabilities {
                    tools: ToolsCapability {
                        list_changed: false,
                    },
                },
                server_info: ServerInfo {
                    name: SERVER_NAME.to_string(),
                    version: SERVER_VERSION.to_string(),
                },
            };
            let value = serde_json::to_value(result).unwrap_or_default();
            JsonRpcResponse::success(id, value)
        }
        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
        "tools/list" => {
            let tools = get_tool_definitions();
            let result = ToolsListResult { tools };
            let value = serde_json::to_value(result).unwrap_or_default();
            JsonRpcResponse::success(id, value)
        }
        "tools/call" => {
            let result = handle_tool_call(&request.params).await;
            let value = serde_json::to_value(result).unwrap_or_default();
            JsonRpcResponse::success(id, value)
        }
        _ => {
            warn!("Unknown method: {}", request.method);
            JsonRpcResponse::error(id, -32601, format!("Method not found: {}", request.method))
        }
    }
}

async fn handle_tool_call(params: &Value) -> ToolCallResult {
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Map::default()));

    match tool_name {
        "audit_package" => handle_audit_package(&arguments).await,
        "check_typosquat" => handle_check_typosquat(&arguments),
        "pin_dependencies" => handle_pin_dependencies(&arguments),
        "scan_lockfile" => handle_scan_lockfile(&arguments).await,
        "get_package_metadata" => handle_get_package_metadata(&arguments).await,
        "audit_project" => handle_audit_project(&arguments),
        "blocklist_status" => handle_blocklist_status(),
        "update_db" => handle_update_db(&arguments).await,
        _ => ToolCallResult::error(format!("Unknown tool: {tool_name}")),
    }
}

async fn handle_audit_package(args: &Value) -> ToolCallResult {
    let Some(ecosystem_str) = args.get("ecosystem").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: ecosystem".to_string());
    };
    let Some(package_name) = args.get("package_name").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: package_name".to_string());
    };
    let Some(version) = args.get("version").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: version".to_string());
    };

    let ecosystem = match data::Ecosystem::from_str(ecosystem_str) {
        Ok(e) => e,
        Err(e) => return ToolCallResult::error(e.to_string()),
    };

    let check_network = args
        .get("check_network")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let check_filesystem = args
        .get("check_filesystem")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let check_processes = args
        .get("check_processes")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    match audit::audit_package(
        ecosystem,
        package_name,
        version,
        check_network,
        check_filesystem,
        check_processes,
    )
    .await
    {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("Audit failed: {e}")),
    }
}

fn handle_check_typosquat(args: &Value) -> ToolCallResult {
    let Some(ecosystem_str) = args.get("ecosystem").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: ecosystem".to_string());
    };
    let Some(package_name) = args.get("package_name").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: package_name".to_string());
    };

    let ecosystem = match data::Ecosystem::from_str(ecosystem_str) {
        Ok(e) => e,
        Err(e) => return ToolCallResult::error(e.to_string()),
    };

    let result = typosquat::check_typosquat(ecosystem, package_name);
    let json = serde_json::to_string_pretty(&result).unwrap_or_default();
    ToolCallResult::text(json)
}

fn handle_pin_dependencies(args: &Value) -> ToolCallResult {
    let Some(file_path) = args.get("file_path").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: file_path".to_string());
    };
    let generate_hashes = args
        .get("generate_hashes")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fix_in_place = args
        .get("fix_in_place")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match parsers::pin_dependencies(file_path, generate_hashes, fix_in_place) {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("Failed to analyze dependencies: {e}")),
    }
}

async fn handle_scan_lockfile(args: &Value) -> ToolCallResult {
    let Some(file_path) = args.get("file_path").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: file_path".to_string());
    };

    match parsers::scan_lockfile_with_osv(file_path).await {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("Failed to scan lockfile: {e}")),
    }
}

async fn handle_get_package_metadata(args: &Value) -> ToolCallResult {
    let Some(ecosystem_str) = args.get("ecosystem").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: ecosystem".to_string());
    };
    let Some(package_name) = args.get("package_name").and_then(Value::as_str) else {
        return ToolCallResult::error("Missing required parameter: package_name".to_string());
    };
    let version = args.get("version").and_then(Value::as_str);

    let ecosystem = match data::Ecosystem::from_str(ecosystem_str) {
        Ok(e) => e,
        Err(e) => return ToolCallResult::error(e.to_string()),
    };

    match registry::get_package_metadata(ecosystem, package_name, version).await {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("Failed to fetch metadata: {e}")),
    }
}

fn handle_audit_project(args: &Value) -> ToolCallResult {
    let project_path = args
        .get("project_path")
        .and_then(Value::as_str)
        .unwrap_or(".");

    match project::audit_project(project_path) {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("Project audit failed: {e}")),
    }
}

fn handle_blocklist_status() -> ToolCallResult {
    let snap = data::custom_blocklist::snapshot();
    let (seed_py, seed_npm, seed_java, seed_cargo) = data::blocklist::seed_entry_counts();
    let status = serde_json::json!({
        "lookup_order": ["custom", "feed_cache", "seed"],
        "custom": {
            "candidate_paths": data::custom_blocklist::candidate_paths(),
            "loaded_paths": snap.loaded_paths,
            "total_entries": snap.total_entries(),
            "load_errors": snap.errors,
        },
        "feed_cache": data::feed_cache::status_snapshot(),
        "seed": {
            "source": "data/blocklist/seed.json (embedded)",
            "python": seed_py,
            "npm": seed_npm,
            "java": seed_java,
            "cargo": seed_cargo,
        },
        "default_feeds": "data/blocklist/default-feeds.json (used by update_db when no feeds given)",
        "osv": "OSV.dev version advisories used by audit_package and scan_lockfile",
    });
    match serde_json::to_string_pretty(&status) {
        Ok(json) => ToolCallResult::text(json),
        Err(e) => ToolCallResult::error(format!("Failed to serialize status: {e}")),
    }
}

async fn handle_update_db(args: &Value) -> ToolCallResult {
    let feeds: Vec<String> = args
        .get("feeds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    match data::update_db::update_db(&feeds).await {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("update_db failed: {e}")),
    }
}
