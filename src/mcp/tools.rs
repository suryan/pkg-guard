//! MCP tool definitions — schemas for each tool exposed by pkg-guard

use super::protocol::ToolDefinition;
use serde_json::json;

/// Return all tool definitions for the MCP `tools/list` response.
pub fn get_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        audit_package_tool(),
        check_typosquat_tool(),
        pin_dependencies_tool(),
        scan_lockfile_tool(),
        get_package_metadata_tool(),
    ]
}

fn audit_package_tool() -> ToolDefinition {
    ToolDefinition {
        name: "audit_package".to_string(),
        description: "Audit a software package for security risks. Checks for typosquatting, \
            verifies registry metadata, and optionally runs isolated container audit \
            monitoring network/filesystem/process activity during installation."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "enum": ["python", "npm", "java"],
                    "description": "Package ecosystem"
                },
                "package_name": {
                    "type": "string",
                    "description": "Package name (for Java use groupId:artifactId format)"
                },
                "version": {
                    "type": "string",
                    "description": "Exact version to audit"
                },
                "check_network": {
                    "type": "boolean",
                    "description": "Monitor network calls during install (default: true)",
                    "default": true
                },
                "check_filesystem": {
                    "type": "boolean",
                    "description": "Monitor filesystem writes during install (default: true)",
                    "default": true
                },
                "check_processes": {
                    "type": "boolean",
                    "description": "Monitor process spawning during install (default: true)",
                    "default": true
                }
            },
            "required": ["ecosystem", "package_name", "version"]
        }),
    }
}

fn check_typosquat_tool() -> ToolDefinition {
    ToolDefinition {
        name: "check_typosquat".to_string(),
        description: "Check if a package name is suspiciously similar to a popular/legitimate \
            package. Detects typosquatting attempts using Levenshtein distance and \
            pattern matching."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "enum": ["python", "npm", "java"],
                    "description": "Package ecosystem"
                },
                "package_name": {
                    "type": "string",
                    "description": "Package name to check"
                }
            },
            "required": ["ecosystem", "package_name"]
        }),
    }
}

fn pin_dependencies_tool() -> ToolDefinition {
    ToolDefinition {
        name: "pin_dependencies".to_string(),
        description: "Scan a dependency file (requirements.txt, package.json, pom.xml) and \
            report which dependencies are not pinned to exact versions. Optionally \
            suggests fixes."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the dependency file"
                },
                "generate_hashes": {
                    "type": "boolean",
                    "description": "Whether to include hash generation in fix suggestions",
                    "default": false
                },
                "fix_in_place": {
                    "type": "boolean",
                    "description": "Whether to provide fix suggestions",
                    "default": false
                }
            },
            "required": ["file_path"]
        }),
    }
}

fn scan_lockfile_tool() -> ToolDefinition {
    ToolDefinition {
        name: "scan_lockfile".to_string(),
        description: "Scan a lock file for known malicious or compromised package versions. \
            Checks against the built-in blocklist database."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the lock file (package-lock.json, yarn.lock, Pipfile.lock, etc.)"
                }
            },
            "required": ["file_path"]
        }),
    }
}

fn get_package_metadata_tool() -> ToolDefinition {
    ToolDefinition {
        name: "get_package_metadata".to_string(),
        description: "Fetch package metadata from the public registry (PyPI, npm, Maven \
            Central) without installing. Shows maintainers, dependencies, install \
            scripts, etc."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "enum": ["python", "npm", "java"],
                    "description": "Package ecosystem"
                },
                "package_name": {
                    "type": "string",
                    "description": "Package name"
                },
                "version": {
                    "type": "string",
                    "description": "Specific version (optional, defaults to latest)"
                }
            },
            "required": ["ecosystem", "package_name"]
        }),
    }
}
