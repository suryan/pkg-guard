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
use crate::{audit, data, osv, parsers, project, registry, typosquat};

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
        "osv_status" => handle_osv_status().await,
        "osv_update" => handle_osv_update(&arguments).await,
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
        "default_feeds": "data/blocklist/default-feeds.json (URL list only; enable + host feeds yourself)",
        "osv": osv::status_snapshot(),
        "hints": [
            "No denylist is embedded in the binary",
            "update_db --feed <url> to load name blocklists",
            "osv_update / pkg-guard osv update for local OSV dumps",
            "blocklist init for zero-day custom names",
        ],
    });
    match serde_json::to_string_pretty(&status) {
        Ok(json) => ToolCallResult::text(json),
        Err(e) => ToolCallResult::error(format!("Failed to serialize status: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn handle_check_and_errors() {
        let r = handle_check_typosquat(&json!({
            "ecosystem": "python",
            "package_name": "requests"
        }));
        assert!(r.is_error.is_none());
        let r = handle_check_typosquat(&json!({"ecosystem": "python"}));
        assert_eq!(r.is_error, Some(true));
        let r = handle_check_typosquat(&json!({
            "ecosystem": "nope",
            "package_name": "x"
        }));
        assert_eq!(r.is_error, Some(true));
    }

    #[test]
    fn handle_pin_and_blocklist_status() {
        let dir = std::env::temp_dir().join(format!("mcp-pin-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("requirements.txt");
        std::fs::write(&f, "flask\nrequests==2.0.0\n").unwrap();
        let r = handle_pin_dependencies(&json!({
            "file_path": f.to_str().unwrap(),
            "fix_in_place": true
        }));
        assert!(r.is_error.is_none());
        let r = handle_pin_dependencies(&json!({}));
        assert_eq!(r.is_error, Some(true));
        let r = handle_blocklist_status();
        assert!(r.is_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_request_initialize_and_tools() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "initialize".into(),
            params: json!({}),
        };
        let resp = handle_request(&req).await;
        assert!(resp.error.is_none());
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(2)),
            method: "tools/list".into(),
            params: json!({}),
        };
        let resp = handle_request(&req).await;
        assert!(resp.result.is_some());
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(3)),
            method: "ping".into(),
            params: json!({}),
        };
        let resp = handle_request(&req).await;
        assert!(resp.error.is_none());
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(4)),
            method: "nope".into(),
            params: json!({}),
        };
        let resp = handle_request(&req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn handle_tool_call_routing() {
        let r = handle_tool_call(&json!({
            "name": "check_typosquat",
            "arguments": {"ecosystem": "npm", "package_name": "lodash"}
        }))
        .await;
        assert!(r.is_error.is_none());
        let r = handle_tool_call(&json!({"name": "unknown_tool", "arguments": {}})).await;
        assert_eq!(r.is_error, Some(true));
        let r = handle_tool_call(&json!({
            "name": "blocklist_status",
            "arguments": {}
        }))
        .await;
        assert!(r.is_error.is_none());
        let r = handle_tool_call(&json!({
            "name": "audit_project",
            "arguments": {"project_path": "/tmp"}
        }))
        .await;
        // /tmp may be empty of manifests — still should not hard-error always
        let _ = r.is_error;
    }

    #[tokio::test]
    async fn handle_audit_package_param_errors_and_no_container() {
        assert_eq!(handle_audit_package(&json!({})).await.is_error, Some(true));
        assert_eq!(
            handle_audit_package(&json!({"ecosystem": "python"}))
                .await
                .is_error,
            Some(true)
        );
        assert_eq!(
            handle_audit_package(&json!({
                "ecosystem": "python",
                "package_name": "six"
            }))
            .await
            .is_error,
            Some(true)
        );
        assert_eq!(
            handle_audit_package(&json!({
                "ecosystem": "nope",
                "package_name": "x",
                "version": "1"
            }))
            .await
            .is_error,
            Some(true)
        );
        let r = handle_audit_package(&json!({
            "ecosystem": "python",
            "package_name": "six",
            "version": "1.16.0",
            "check_network": false,
            "check_filesystem": false,
            "check_processes": false
        }))
        .await;
        assert!(r.is_error.is_none(), "{r:?}");
    }

    #[tokio::test]
    async fn handle_scan_metadata_and_update_db_paths() {
        let dir = std::env::temp_dir().join(format!("mcp-scan-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("requirements.txt");
        std::fs::write(&f, "six==1.16.0\n").unwrap();

        assert_eq!(handle_scan_lockfile(&json!({})).await.is_error, Some(true));
        let r = handle_scan_lockfile(&json!({
            "file_path": f.to_str().unwrap()
        }))
        .await;
        assert!(r.is_error.is_none());

        assert_eq!(
            handle_get_package_metadata(&json!({})).await.is_error,
            Some(true)
        );
        assert_eq!(
            handle_get_package_metadata(&json!({"ecosystem": "python"}))
                .await
                .is_error,
            Some(true)
        );
        assert_eq!(
            handle_get_package_metadata(&json!({
                "ecosystem": "zzz",
                "package_name": "x"
            }))
            .await
            .is_error,
            Some(true)
        );
        let r = handle_get_package_metadata(&json!({
            "ecosystem": "python",
            "package_name": "six",
            "version": "1.16.0"
        }))
        .await;
        assert!(r.is_error.is_none());

        assert_eq!(
            handle_audit_project(&json!({
                "project_path": dir.join("missing-dir").to_str().unwrap()
            }))
            .is_error,
            Some(true)
        );

        // tools/call wrappers for audit_package and update_db empty feeds
        let r = handle_tool_call(&json!({
            "name": "audit_package",
            "arguments": {
                "ecosystem": "npm",
                "package_name": "left-pad",
                "version": "1.3.0",
                "check_network": false,
                "check_filesystem": false,
                "check_processes": false
            }
        }))
        .await;
        assert!(r.is_error.is_none());

        let r = handle_tool_call(&json!({
            "name": "update_db",
            "arguments": {"feeds": []}
        }))
        .await;
        // no feeds configured → error path
        assert_eq!(r.is_error, Some(true));

        let r = handle_tool_call(&json!({
            "name": "get_package_metadata",
            "arguments": {
                "ecosystem": "cargo",
                "package_name": "serde"
            }
        }))
        .await;
        assert!(r.is_error.is_none());

        let r = handle_tool_call(&json!({
            "name": "scan_lockfile",
            "arguments": {"file_path": f.to_str().unwrap()}
        }))
        .await;
        assert!(r.is_error.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_request_tools_call() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(9)),
            method: "tools/call".into(),
            params: json!({
                "name": "check_typosquat",
                "arguments": {"ecosystem": "python", "package_name": "flask"}
            }),
        };
        let resp = handle_request(&req).await;
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn handle_osv_status_ok() {
        let r = handle_osv_status().await;
        assert!(r.is_error.is_none());
    }

    #[tokio::test]
    async fn handle_osv_update_bad_ecosystem() {
        let r = handle_osv_update(&json!({
            "ecosystems": ["not-an-eco"]
        }))
        .await;
        assert_eq!(r.is_error, Some(true));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn handle_osv_update_all_fail() {
        std::env::set_var("PKG_GUARD_OSV_DUMP_BASE", "http://127.0.0.1:1");
        let r = handle_osv_update(&json!({
            "ecosystems": ["cargo"]
        }))
        .await;
        assert_eq!(r.is_error, Some(true));
        std::env::remove_var("PKG_GUARD_OSV_DUMP_BASE");
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
    let also_osv = args.get("osv").and_then(Value::as_bool).unwrap_or(false);

    match data::update_db::update_db(&feeds).await {
        Ok(result) => {
            if also_osv {
                match osv::update_osv(&[], false).await {
                    Ok(osv_result) => {
                        let combined = serde_json::json!({
                            "feeds": result,
                            "osv": osv_result,
                        });
                        let json = serde_json::to_string_pretty(&combined).unwrap_or_default();
                        ToolCallResult::text(json)
                    }
                    Err(e) => {
                        ToolCallResult::error(format!("feeds updated but osv update failed: {e}"))
                    }
                }
            } else {
                let json = serde_json::to_string_pretty(&result).unwrap_or_default();
                ToolCallResult::text(json)
            }
        }
        Err(e) => ToolCallResult::error(format!("update_db failed: {e}")),
    }
}

async fn handle_osv_status() -> ToolCallResult {
    match serde_json::to_string_pretty(&osv::status_with_remote().await) {
        Ok(json) => ToolCallResult::text(json),
        Err(e) => ToolCallResult::error(format!("Failed to serialize OSV status: {e}")),
    }
}

async fn handle_osv_update(args: &Value) -> ToolCallResult {
    let mut ecos = Vec::new();
    if let Some(arr) = args.get("ecosystems").and_then(Value::as_array) {
        for v in arr {
            let Some(s) = v.as_str() else {
                continue;
            };
            match data::Ecosystem::from_str(s) {
                Ok(e) => ecos.push(e),
                Err(e) => return ToolCallResult::error(e.to_string()),
            }
        }
    }
    let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
    match osv::update_osv(&ecos, force).await {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
            ToolCallResult::text(json)
        }
        Err(e) => ToolCallResult::error(format!("osv_update failed: {e}")),
    }
}
