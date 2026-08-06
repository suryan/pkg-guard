//! Shared data types and embedded blocklist

pub mod blocklist;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

/// Supported package ecosystems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// Python packages (pip/PyPI)
    Python,
    /// Node.js packages (npm)
    Npm,
    /// Java packages (Maven/Gradle)
    Java,
}

impl Ecosystem {
    /// Parse an ecosystem from a string identifier.
    ///
    /// # Errors
    /// Returns an error if the string doesn't match a known ecosystem.
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "python" | "pip" | "pypi" => Ok(Self::Python),
            "npm" | "node" | "nodejs" => Ok(Self::Npm),
            "java" | "maven" | "gradle" => Ok(Self::Java),
            _ => Err(anyhow!(
                "Unsupported ecosystem: '{s}'. Use: python, npm, or java"
            )),
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Python => write!(f, "python"),
            Self::Npm => write!(f, "npm"),
            Self::Java => write!(f, "java"),
        }
    }
}

/// Result status from an audit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditStatus {
    /// Package passed all checks
    Pass,
    /// Package has warnings but is not blocked
    Warning,
    /// Package is blocked due to security risks
    Blocked,
    /// Audit could not complete
    Failed,
}

/// Full audit result
#[derive(Debug, Serialize)]
pub struct AuditResult {
    /// Overall audit status
    pub status: AuditStatus,
    /// Package name that was audited
    pub package: String,
    /// Version that was audited
    pub version: String,
    /// Ecosystem of the package
    pub ecosystem: Ecosystem,
    /// Warning messages collected during audit
    pub warnings: Vec<String>,
    /// Typosquat check results
    pub typosquat_check: TyposquatResult,
    /// Registry metadata (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Container audit results (if performed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_audit: Option<ContainerAuditResult>,
    /// Human-readable recommendation
    pub recommendation: String,
}

/// Typosquat check result
#[derive(Debug, Serialize, Deserialize)]
pub struct TyposquatResult {
    /// Whether the package name is suspicious
    pub is_suspicious: bool,
    /// Whether the package is on the blocklist
    pub is_blocklisted: bool,
    /// Similar legitimate packages found
    pub similar_to: Vec<String>,
    /// Minimum edit distance to a popular package
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_levenshtein_distance: Option<usize>,
    /// Human-readable recommendation
    pub recommendation: String,
}

/// Container audit findings
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerAuditResult {
    /// Whether the package installed successfully
    pub install_success: bool,
    /// Suspicious activity flags
    pub suspicious_activity: SuspiciousActivity,
    /// Network-related findings
    pub network_findings: Vec<String>,
    /// Filesystem-related findings
    pub filesystem_findings: Vec<String>,
    /// Process-related findings
    pub process_findings: Vec<String>,
    /// Error message if audit infrastructure failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Suspicious activity flags from container audit
#[derive(Debug, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    /// Suspicious network connections detected
    pub network: bool,
    /// Suspicious filesystem writes detected
    pub filesystem: bool,
    /// Suspicious process spawning detected
    pub processes: bool,
}

/// Dependency pinning result
#[derive(Debug, Serialize)]
pub struct PinResult {
    /// Path to the file analyzed
    pub file: String,
    /// Total number of dependencies found
    pub total_dependencies: usize,
    /// Number of properly pinned dependencies
    pub pinned_count: usize,
    /// Number of unpinned dependencies
    pub unpinned_count: usize,
    /// Details of unpinned dependencies
    pub unpinned: Vec<UnpinnedDep>,
    /// Details of pinned dependencies
    pub pinned: Vec<PinnedDep>,
    /// Summary score (e.g., "4/10 pinned")
    pub score: String,
    /// Human-readable recommendation
    pub recommendation: String,
    /// Fix suggestion if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
}

/// An unpinned dependency
#[derive(Debug, Serialize)]
pub struct UnpinnedDep {
    /// Package name
    pub package: String,
    /// Current version constraint
    pub constraint: String,
    /// Description of the pinning issue
    pub issue: String,
    /// Which section of the file (e.g., "dependencies", "devDependencies")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

/// A properly pinned dependency
#[derive(Debug, Serialize)]
pub struct PinnedDep {
    /// Package name
    pub package: String,
    /// Pinned version
    pub version: String,
    /// Whether hash verification is present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_hash: Option<bool>,
    /// Which section of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

/// Lock file scan result
#[derive(Debug, Serialize)]
pub struct ScanResult {
    /// Path to the file scanned
    pub file: String,
    /// Malicious packages found
    pub malicious_findings: Vec<MaliciousFinding>,
    /// Number of findings
    pub findings_count: usize,
    /// Overall status message
    pub status: String,
}

/// A finding of a malicious package in a lock file
#[derive(Debug, Serialize)]
pub struct MaliciousFinding {
    /// Package name
    pub package: String,
    /// Version (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Severity level
    pub severity: String,
    /// Reason for flagging
    pub reason: String,
}

/// Kind of project file discovered during a project-wide audit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectFileKind {
    /// Dependency manifest (requirements.txt, package.json, pom.xml, …)
    Manifest,
    /// Lock file (package-lock.json, yarn.lock, …)
    Lockfile,
}

/// Per-file result inside a project audit
#[derive(Debug, Serialize)]
pub struct ProjectFileResult {
    /// Path relative to the project root
    pub path: String,
    /// Manifest vs lockfile
    pub kind: ProjectFileKind,
    /// Pin analysis (manifests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<PinResult>,
    /// Blocklist scan (lockfiles and requirements blocklist pass)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanResult>,
    /// Error if this file could not be analyzed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregate result of scanning an entire project tree
#[derive(Debug, Serialize)]
pub struct ProjectAuditResult {
    /// Absolute (or best-effort) project path
    pub project_path: String,
    /// Number of supported files analyzed
    pub files_scanned: usize,
    /// Total unpinned dependency declarations across manifests
    pub total_unpinned: usize,
    /// Total malicious findings across lock/dep files
    pub total_malicious: usize,
    /// Overall status: CLEAN | WARNING | CRITICAL | EMPTY
    pub status: String,
    /// Human-readable recommendation
    pub recommendation: String,
    /// Per-file results
    pub files: Vec<ProjectFileResult>,
}
