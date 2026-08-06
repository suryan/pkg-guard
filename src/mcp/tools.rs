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
        audit_project_tool(),
        blocklist_status_tool(),
        update_db_tool(),
        osv_status_tool(),
        osv_update_tool(),
    ]
}

fn audit_package_tool() -> ToolDefinition {
    ToolDefinition {
        name: "audit_package".to_string(),
        description: "Audit a software package for security risks. Checks for typosquatting, \
            OSV.dev version advisories (CVE/MAL), registry metadata, and optionally runs \
            isolated container audit monitoring network/filesystem/process activity."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "enum": ["python", "npm", "java", "cargo"],
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
                    "enum": ["python", "npm", "java", "cargo"],
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
        description: "Scan a lock file for known malicious packages (custom + feed-cache \
            blocklists; nothing embedded in the binary) and OSV.dev version advisories."
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
                    "enum": ["python", "npm", "java", "cargo"],
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

fn audit_project_tool() -> ToolDefinition {
    ToolDefinition {
        name: "audit_project".to_string(),
        description: "Scan an entire project directory for dependency pinning issues and \
            known-malicious packages. Discovers requirements.txt, package.json, pom.xml, \
            build.gradle, package-lock.json, yarn.lock, Pipfile.lock, and similar files."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Path to the project root directory (default: current directory)",
                    "default": "."
                }
            },
            "required": []
        }),
    }
}

fn blocklist_status_tool() -> ToolDefinition {
    ToolDefinition {
        name: "blocklist_status".to_string(),
        description: "Show blocklist layer status: custom lists and feed cache \
            (no embedded denylist). Lookup order is custom → feed_cache."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

fn update_db_tool() -> ToolDefinition {
    ToolDefinition {
        name: "update_db".to_string(),
        description: "Refresh the feed cache from remote feed URLs only (no embedded seed). \
            Requires --feed / feeds[] / PKG_GUARD_FEED_URLS / enabled default-feeds. \
            Writes ~/.cache/pkg-guard/blocklist-cache.json. Set osv=true to also download OSV dumps."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "feeds": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional extra feed URLs (JSON blocklist documents). Defaults from PKG_GUARD_FEED_URLS and data/blocklist/default-feeds.json apply when empty."
                },
                "osv": {
                    "type": "boolean",
                    "description": "Also download OSV ecosystem dumps and build local indexes (default: false)",
                    "default": false
                }
            },
            "required": []
        }),
    }
}

fn osv_status_tool() -> ToolDefinition {
    ToolDefinition {
        name: "osv_status".to_string(),
        description: "Show local OSV dump status (path, age, ecosystems) and lookup mode \
            (PKG_GUARD_OSV_MODE=auto|local|online)."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}

fn osv_update_tool() -> ToolDefinition {
    ToolDefinition {
        name: "osv_update".to_string(),
        description: "Download OSV.dev ecosystem dumps (PyPI/npm/Maven/crates.io) from the public \
            GCS bucket and build a local package→advisory index for offline scanning. \
            Large ecosystems (npm) may take several minutes and ~200MB+ download."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystems": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["python", "npm", "java", "cargo"]
                    },
                    "description": "Ecosystems to download (default: all four)"
                }
            },
            "required": []
        }),
    }
}
