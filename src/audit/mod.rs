//! Container audit orchestrator
//!
//! Installs packages in isolated Docker containers and monitors for suspicious
//! behavior using the bollard Docker API. No shelling out to the docker CLI.
//!
//! Monitors:
//! - Network activity (unexpected outbound connections)
//! - Filesystem writes (outside expected install paths)
//! - Process spawning (reverse shells, crypto miners)

use anyhow::{anyhow, Result};
use bollard::container::{
    Config, CreateContainerOptions, LogOutput, LogsOptions, RemoveContainerOptions,
    StartContainerOptions, WaitContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::StreamExt;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::data::{AuditResult, AuditStatus, ContainerAuditResult, Ecosystem, SuspiciousActivity};
use crate::osv;
use crate::registry;
use crate::typosquat;

/// Maximum time (seconds) to wait for a container audit to complete.
const AUDIT_TIMEOUT_SECS: u64 = 120;

/// Memory limit for audit containers (512 MB).
const MEMORY_LIMIT: i64 = 512 * 1024 * 1024;

/// PID limit for audit containers.
const PIDS_LIMIT: i64 = 100;

/// Run a full audit of a package.
///
/// # Errors
/// Returns an error if the audit infrastructure fails catastrophically.
pub async fn audit_package(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
    check_network: bool,
    check_filesystem: bool,
    check_processes: bool,
) -> Result<AuditResult> {
    // Step 1: Typosquat check
    let typosquat_result = typosquat::check_typosquat(ecosystem, package_name);

    if typosquat_result.is_blocklisted {
        let source = typosquat_result
            .blocklist_source
            .as_deref()
            .unwrap_or("builtin");
        let warning = match source {
            "custom" => "Package is on your custom blocklist (user/project/env)".to_string(),
            "feed" => "Package is on the feed cache blocklist (pkg-guard update-db)".to_string(),
            _ => "Package is on the built-in seed blocklist".to_string(),
        };
        return Ok(AuditResult {
            status: AuditStatus::Blocked,
            package: package_name.to_string(),
            version: version.to_string(),
            ecosystem,
            warnings: vec![warning],
            typosquat_check: typosquat_result,
            metadata: None,
            container_audit: None,
            osv: None,
            recommendation: "DO NOT INSTALL — package is known malicious".to_string(),
        });
    }

    // Step 2: Fetch registry metadata
    let metadata = fetch_metadata(ecosystem, package_name, version).await;

    // Check if package exists
    if let Some(ref meta) = metadata {
        if meta.get("exists") == Some(&Value::Bool(false)) {
            let error_msg = meta
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Ok(AuditResult {
                status: AuditStatus::Failed,
                package: package_name.to_string(),
                version: version.to_string(),
                ecosystem,
                warnings: vec![format!("Package not found on registry: {error_msg}")],
                typosquat_check: typosquat_result,
                metadata,
                container_audit: None,
                osv: None,
                recommendation: "FAILED — package does not exist on the registry".to_string(),
            });
        }
    }

    // Step 2b: OSV version advisories (CVE / MAL-*)
    let osv_result = match osv::query_package(ecosystem, package_name, version).await {
        Ok(r) => Some(r),
        Err(e) => {
            warn!("OSV query failed (continuing audit): {e}");
            Some(osv::OsvQueryResult {
                package: package_name.to_string(),
                version: version.to_string(),
                ecosystem: format!("{ecosystem}"),
                advisories: vec![],
                error: Some(e.to_string()),
            })
        }
    };

    // Step 3 & 4: Collect warnings and run container
    let mut warnings = collect_metadata_warnings(ecosystem, metadata.as_ref());
    apply_osv_warnings(osv_result.as_ref(), &mut warnings);

    let container_audit = run_audit_if_needed(
        ecosystem,
        package_name,
        version,
        check_network,
        check_filesystem,
        check_processes,
    )
    .await;

    // Step 5: Determine overall status
    let mut status = determine_status(&typosquat_result, container_audit.as_ref(), &mut warnings);
    status = elevate_with_osv(status, osv_result.as_ref());

    let recommendation = match status {
        AuditStatus::Pass => "SAFE to install — pin exact version with hash".to_string(),
        AuditStatus::Warning => {
            "REVIEW REQUIRED — proceed with caution after manual review".to_string()
        }
        AuditStatus::Blocked => "DO NOT INSTALL — security risks detected".to_string(),
        AuditStatus::Failed => "FAILED — could not complete audit".to_string(),
    };

    Ok(AuditResult {
        status,
        package: package_name.to_string(),
        version: version.to_string(),
        ecosystem,
        warnings,
        typosquat_check: typosquat_result,
        metadata,
        container_audit,
        osv: osv_result,
        recommendation,
    })
}

async fn fetch_metadata(ecosystem: Ecosystem, package_name: &str, version: &str) -> Option<Value> {
    match registry::get_package_metadata(ecosystem, package_name, Some(version)).await {
        Ok(m) => Some(m),
        Err(e) => {
            warn!("Failed to fetch metadata: {e}");
            None
        }
    }
}

fn collect_metadata_warnings(ecosystem: Ecosystem, metadata: Option<&Value>) -> Vec<String> {
    let mut warnings = Vec::new();
    if ecosystem == Ecosystem::Npm {
        if let Some(meta) = metadata {
            if meta.get("has_install_scripts") == Some(&Value::Bool(true)) {
                warnings.push(
                    "Package has install-time scripts (preinstall/postinstall) — \
                     these execute arbitrary code during npm install"
                        .to_string(),
                );
            }
        }
    }
    warnings
}

async fn run_audit_if_needed(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
    check_network: bool,
    check_filesystem: bool,
    check_processes: bool,
) -> Option<ContainerAuditResult> {
    if !check_network && !check_filesystem && !check_processes {
        return None;
    }

    match run_container_audit(
        ecosystem,
        package_name,
        version,
        check_network,
        check_filesystem,
        check_processes,
    )
    .await
    {
        Ok(result) => Some(result),
        Err(e) => {
            warn!("Container audit failed: {e}");
            Some(ContainerAuditResult {
                install_success: false,
                suspicious_activity: SuspiciousActivity {
                    network: false,
                    filesystem: false,
                    processes: false,
                },
                network_findings: vec![],
                filesystem_findings: vec![],
                process_findings: vec![],
                error: Some(format!("Container audit unavailable: {e}")),
            })
        }
    }
}

fn apply_osv_warnings(osv: Option<&osv::OsvQueryResult>, warnings: &mut Vec<String>) {
    let Some(osv) = osv else {
        return;
    };
    if let Some(err) = &osv.error {
        warnings.push(format!("OSV advisory lookup incomplete: {err}"));
        return;
    }
    for adv in &osv.advisories {
        let kind = if adv.is_malware {
            "MALWARE"
        } else {
            "advisory"
        };
        warnings.push(format!(
            "OSV {kind} {} ({}) — {}",
            adv.id, adv.severity, adv.summary
        ));
    }
}

fn elevate_with_osv(status: AuditStatus, osv: Option<&osv::OsvQueryResult>) -> AuditStatus {
    let Some(osv) = osv else {
        return status;
    };
    if osv.has_malware() {
        return elevate(status, AuditStatus::Blocked);
    }
    if osv.has_critical_or_high() {
        return elevate(status, AuditStatus::Blocked);
    }
    if !osv.advisories.is_empty() {
        return elevate(status, AuditStatus::Warning);
    }
    status
}

/// Elevate status only toward higher severity: Pass < Warning < Blocked < Failed.
fn elevate(current: AuditStatus, next: AuditStatus) -> AuditStatus {
    use AuditStatus::{Blocked, Failed, Pass, Warning};
    match (current, next) {
        (Failed, _) | (_, Failed) => Failed,
        (Blocked, _) | (_, Blocked) => Blocked,
        (Warning, _) | (_, Warning) => Warning,
        (Pass, Pass) => Pass,
    }
}

fn determine_status(
    typosquat_result: &crate::data::TyposquatResult,
    container_audit: Option<&ContainerAuditResult>,
    warnings: &mut Vec<String>,
) -> AuditStatus {
    let mut status = AuditStatus::Pass;

    // Install-time scripts already added as warnings → WARN (not block by default)
    if !warnings.is_empty() {
        status = elevate(status, AuditStatus::Warning);
    }

    if typosquat_result.is_suspicious {
        warnings.push(format!(
            "Typosquat warning: similar to {:?}",
            typosquat_result.similar_to
        ));
        status = elevate(status, AuditStatus::Warning);
    }

    if let Some(audit) = container_audit {
        // Network / process abuse are hard blocks
        if audit.suspicious_activity.network {
            warnings.push("Suspicious network activity detected during installation".to_string());
            status = elevate(status, AuditStatus::Blocked);
        }
        if audit.suspicious_activity.processes {
            warnings.push("Suspicious process spawning detected during installation".to_string());
            status = elevate(status, AuditStatus::Blocked);
        }
        // Filesystem noise is a review warning unless findings look critical
        if audit.suspicious_activity.filesystem {
            let critical = audit
                .filesystem_findings
                .iter()
                .any(|f| is_critical_fs_finding(f));
            if critical {
                warnings.push(
                    "Critical filesystem writes detected during installation (e.g. ssh/cron)"
                        .to_string(),
                );
                status = elevate(status, AuditStatus::Blocked);
            } else {
                warnings.push(format!(
                    "Unexpected filesystem activity during installation: {}",
                    audit.filesystem_findings.join("; ")
                ));
                status = elevate(status, AuditStatus::Warning);
            }
        }
        if !audit.install_success && audit.error.is_none() {
            warnings.push("Package failed to install in isolated environment".to_string());
            status = elevate(status, AuditStatus::Warning);
        }
        if audit.error.is_some() {
            status = elevate(status, AuditStatus::Warning);
        }
    }

    status
}

/// Paths that indicate real compromise rather than package-manager noise.
fn is_critical_fs_finding(finding: &str) -> bool {
    let lower = finding.to_lowercase();
    lower.contains("/.ssh")
        || lower.contains("authorized_keys")
        || lower.contains("crontab")
        || lower.contains("/etc/passwd")
        || lower.contains("/etc/shadow")
        || lower.contains("/etc/sudoers")
        || lower.contains("/var/spool/cron")
}

/// Run the container-based audit using Docker.
async fn run_container_audit(
    ecosystem: Ecosystem,
    package_name: &str,
    version: &str,
    check_network: bool,
    check_filesystem: bool,
    check_processes: bool,
) -> Result<ContainerAuditResult> {
    let docker = Docker::connect_with_local_defaults()
        .map_err(|e| anyhow!("Cannot connect to Docker: {e}. Is Docker running?"))?;

    docker
        .ping()
        .await
        .map_err(|e| anyhow!("Docker daemon not responding: {e}"))?;

    let (image, install_cmd) = get_install_config(ecosystem, package_name, version);

    info!("Pulling image: {image}");
    pull_image(&docker, &image).await?;

    let audit_script = build_audit_script(
        &install_cmd,
        check_network,
        check_filesystem,
        check_processes,
    );
    let container_name = format!(
        "pkg-guard-{ecosystem}-{}-{}",
        package_name.replace(['/', ':', '@'], "-"),
        std::process::id()
    );

    debug!("Creating audit container: {container_name}");

    let container = create_audit_container(&docker, &container_name, &image, audit_script).await?;

    docker
        .start_container(&container.id, None::<StartContainerOptions<String>>)
        .await
        .map_err(|e| anyhow!("Failed to start container: {e}"))?;

    info!("Container started, waiting for completion...");

    let exit_code = wait_with_timeout(&docker, &container.id).await?;
    let logs = collect_logs(&docker, &container.id).await;
    cleanup_container(&docker, &container.id).await;

    Ok(parse_audit_output(&logs, exit_code))
}

async fn create_audit_container(
    docker: &Docker,
    name: &str,
    image: &str,
    audit_script: String,
) -> Result<bollard::models::ContainerCreateResponse> {
    let host_config = bollard::models::HostConfig {
        memory: Some(MEMORY_LIMIT),
        pids_limit: Some(PIDS_LIMIT),
        cap_drop: Some(vec!["ALL".to_string()]),
        cap_add: Some(vec!["NET_RAW".to_string()]),
        security_opt: Some(vec!["no-new-privileges".to_string()]),
        ..Default::default()
    };

    let config = Config {
        image: Some(image.to_string()),
        cmd: Some(vec!["sh".to_string(), "-c".to_string(), audit_script]),
        host_config: Some(host_config),
        network_disabled: Some(false),
        ..Default::default()
    };

    docker
        .create_container(
            Some(CreateContainerOptions {
                name,
                platform: None,
            }),
            config,
        )
        .await
        .map_err(|e| anyhow!("Failed to create container: {e}"))
}

async fn wait_with_timeout(docker: &Docker, container_id: &str) -> Result<i64> {
    let wait_result = tokio::time::timeout(
        std::time::Duration::from_secs(AUDIT_TIMEOUT_SECS),
        wait_for_container(docker, container_id),
    )
    .await;

    match wait_result {
        Ok(Ok(code)) => Ok(code),
        Ok(Err(e)) => {
            cleanup_container(docker, container_id).await;
            Err(anyhow!("Error waiting for container: {e}"))
        }
        Err(_) => {
            warn!("Container audit timed out after {AUDIT_TIMEOUT_SECS}s");
            cleanup_container(docker, container_id).await;
            // Return a special exit code to signal timeout
            Ok(-1)
        }
    }
}

/// Get the Docker image and install command for each ecosystem.
fn get_install_config(ecosystem: Ecosystem, package_name: &str, version: &str) -> (String, String) {
    match ecosystem {
        Ecosystem::Python => (
            "python:3.12-slim".to_string(),
            format!("pip install --no-cache-dir --target=/install '{package_name}=={version}'"),
        ),
        Ecosystem::Npm => (
            "node:20-slim".to_string(),
            format!(
                "mkdir -p /install && cd /install && npm init -y >/dev/null 2>&1 \
                 && npm install --prefix /install '{package_name}@{version}'"
            ),
        ),
        Ecosystem::Java => {
            let parts: Vec<&str> = package_name.split(':').collect();
            let (group_id, artifact_id) = if parts.len() == 2 {
                (parts[0], parts[1])
            } else {
                (package_name, package_name)
            };
            (
                "maven:3.9-eclipse-temurin-21".to_string(),
                format!(
                    r"mkdir -p /install && cd /install && cat > pom.xml << 'EOF'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>audit</groupId>
  <artifactId>audit</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>{group_id}</groupId>
      <artifactId>{artifact_id}</artifactId>
      <version>{version}</version>
    </dependency>
  </dependencies>
</project>
EOF
mvn dependency:resolve -q"
                ),
            )
        }
    }
}

/// Build the shell script that runs inside the container.
///
/// Uses a **sentinel file** touched before install so mtime comparisons are
/// stable. Does **not** flag the whole of `/root` (npm/pip write caches there).
/// Pure POSIX shell — no python/node dependency inside the audit image.
fn build_audit_script(
    install_cmd: &str,
    check_network: bool,
    check_filesystem: bool,
    check_processes: bool,
) -> String {
    format!(
        r#"#!/bin/sh
set -u

# Build a JSON string array from newline-separated paths/lines (POSIX).
json_string_array() {{
    printf '['
    first=1
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        esc=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
        if [ "$first" -eq 1 ]; then
            first=0
        else
            printf ','
        fi
        printf '"%s"' "$esc"
    done
    printf ']'
}}

INSTALL_EXIT=0
SUSPICIOUS_NET=false
SUSPICIOUS_FS=false
SUSPICIOUS_PROC=false
NET_FINDINGS="[]"
FS_FINDINGS="[]"
PROC_FINDINGS="[]"

# Stable mtime anchor — never use /install (its mtime moves during install)
touch /tmp/pkg-guard-sentinel
mkdir -p /install

INSTALL_OUTPUT=$({install_cmd} 2>&1) || INSTALL_EXIT=$?

if [ "{check_network}" = "true" ]; then
    SUSPICIOUS_URLS=$(echo "$INSTALL_OUTPUT" | grep -iE '(pastebin|ngrok|burp|interact\.sh|oast|dnslog|requestbin)' | head -5 || true)
    if [ -n "$SUSPICIOUS_URLS" ]; then
        SUSPICIOUS_NET=true
        NET_FINDINGS=$(printf '%s\n' "$SUSPICIOUS_URLS" | json_string_array)
    fi
fi

if [ "{check_filesystem}" = "true" ]; then
    # High-signal paths only. Do not scan all of /root (npm/pip caches).
    CANDIDATES=$(find /etc /var/spool/cron /root/.ssh \
        -newer /tmp/pkg-guard-sentinel -type f 2>/dev/null \
        | grep -Ev '(/etc/ld\.so\.cache|/etc/ssl/certs/|/etc/ca-certificates|/etc/resolv\.conf)' \
        | head -20 || true)
    if [ -n "$CANDIDATES" ]; then
        SUSPICIOUS_FS=true
        FS_FINDINGS=$(printf '%s\n' "$CANDIDATES" | json_string_array)
    fi
fi

if [ "{check_processes}" = "true" ]; then
    PROC_PATTERNS=$(echo "$INSTALL_OUTPUT" | grep -iE '(reverse.?shell|nc -e|bash -i|/dev/tcp|xmrig|stratum\+tcp|cryptonight)' | head -3 || true)
    if [ -n "$PROC_PATTERNS" ]; then
        SUSPICIOUS_PROC=true
        PROC_FINDINGS='["Suspicious process patterns detected in install output"]'
    fi
fi

cat << RESULTEOF
{{
    "install_success": $([ $INSTALL_EXIT -eq 0 ] && echo "true" || echo "false"),
    "suspicious_activity": {{
        "network": $SUSPICIOUS_NET,
        "filesystem": $SUSPICIOUS_FS,
        "processes": $SUSPICIOUS_PROC
    }},
    "network_findings": $NET_FINDINGS,
    "filesystem_findings": $FS_FINDINGS,
    "process_findings": $PROC_FINDINGS
}}
RESULTEOF
"#,
    )
}

/// Pull a Docker image.
async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    let options = Some(CreateImageOptions {
        from_image: image,
        ..Default::default()
    });

    let mut stream = docker.create_image(options, None, None);

    while let Some(result) = stream.next().await {
        match result {
            Ok(info) => {
                debug!("Pull progress: {:?}", info.status);
            }
            Err(e) => {
                return Err(anyhow!("Failed to pull image '{image}': {e}"));
            }
        }
    }

    Ok(())
}

/// Wait for a container to exit and return its exit code.
async fn wait_for_container(docker: &Docker, container_id: &str) -> Result<i64> {
    let options = WaitContainerOptions {
        condition: "not-running",
    };

    let mut stream = docker.wait_container(container_id, Some(options));

    if let Some(result) = stream.next().await {
        match result {
            Ok(response) => return Ok(response.status_code),
            Err(e) => return Err(anyhow!("Error waiting for container: {e}")),
        }
    }

    Err(anyhow!("Wait stream ended without result"))
}

/// Collect all logs from a container.
async fn collect_logs(docker: &Docker, container_id: &str) -> String {
    let options = LogsOptions::<String> {
        stdout: true,
        stderr: true,
        follow: false,
        ..Default::default()
    };

    let mut output = String::new();
    let mut stream = docker.logs(container_id, Some(options));

    while let Some(result) = stream.next().await {
        match result {
            Ok(LogOutput::StdOut { message }) => {
                output.push_str(&String::from_utf8_lossy(&message));
            }
            Ok(LogOutput::StdErr { message }) => {
                debug!("Container stderr: {}", String::from_utf8_lossy(&message));
            }
            Ok(_) => {}
            Err(e) => {
                error!("Error reading logs: {e}");
                break;
            }
        }
    }

    output
}

/// Remove a container (force).
async fn cleanup_container(docker: &Docker, container_id: &str) {
    let options = Some(RemoveContainerOptions {
        force: true,
        ..Default::default()
    });

    if let Err(e) = docker.remove_container(container_id, options).await {
        debug!("Failed to remove container (may already be removed): {e}");
    }
}

/// Parse the JSON output from the audit container.
fn parse_audit_output(logs: &str, exit_code: i64) -> ContainerAuditResult {
    if exit_code == -1 {
        return ContainerAuditResult {
            install_success: false,
            suspicious_activity: SuspiciousActivity {
                network: true,
                filesystem: false,
                processes: false,
            },
            network_findings: vec![
                "Container timed out — possible hang or infinite loop".to_string()
            ],
            filesystem_findings: vec![],
            process_findings: vec![],
            error: Some(format!("Timed out after {AUDIT_TIMEOUT_SECS}s")),
        };
    }

    if let Some(json) = extract_last_json_block(logs) {
        if let Ok(result) = serde_json::from_str::<ContainerAuditResult>(&json) {
            return result;
        }
    }

    // Fallback: couldn't parse JSON output
    ContainerAuditResult {
        install_success: exit_code == 0,
        suspicious_activity: SuspiciousActivity {
            network: false,
            filesystem: false,
            processes: false,
        },
        network_findings: vec![],
        filesystem_findings: vec![],
        process_findings: vec![],
        error: Some(format!(
            "Could not parse container output (exit code: {exit_code}). \
             Last 200 chars: {}",
            &logs[logs.len().saturating_sub(200)..]
        )),
    }
}

/// Extract the last JSON object from a string (handles mixed output).
fn extract_last_json_block(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut start = None;

    // Scan backwards for the last '}' and find its matching '{'
    for i in (0..chars.len()).rev() {
        if chars[i] == '}' {
            let mut depth = 0;
            for j in (0..=i).rev() {
                if chars[j] == '}' {
                    depth += 1;
                } else if chars[j] == '{' {
                    depth -= 1;
                    if depth == 0 {
                        start = Some(j);
                        break;
                    }
                }
            }
            if start.is_some() {
                break;
            }
        }
    }

    start.map(|s| {
        let mut depth = 0;
        let mut end = s;
        for (i, &c) in chars[s..].iter().enumerate() {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth == 0 {
                    end = s + i;
                    break;
                }
            }
        }
        chars[s..=end].iter().collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_from_mixed_output() {
        let output = r#"
Installing package...
Downloading files...
{"install_success": true, "suspicious_activity": {"network": false, "filesystem": false, "processes": false}, "network_findings": [], "filesystem_findings": [], "process_findings": []}
"#;
        let json = extract_last_json_block(output).expect("should find JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");
        assert_eq!(parsed["install_success"], true);
    }

    #[test]
    fn test_extract_json_no_json() {
        let output = "Just some plain text output\nwith no JSON";
        assert!(extract_last_json_block(output).is_none());
    }

    #[test]
    fn test_get_install_config_python() {
        let (image, cmd) = get_install_config(Ecosystem::Python, "requests", "2.31.0");
        assert!(image.contains("python"));
        assert!(cmd.contains("requests==2.31.0"));
    }

    #[test]
    fn test_get_install_config_npm() {
        let (image, cmd) = get_install_config(Ecosystem::Npm, "express", "4.18.2");
        assert!(image.contains("node"));
        assert!(cmd.contains("express@4.18.2"));
    }

    #[test]
    fn test_get_install_config_java() {
        let (image, cmd) =
            get_install_config(Ecosystem::Java, "com.google.guava:guava", "32.1.3-jre");
        assert!(image.contains("maven"));
        assert!(cmd.contains("com.google.guava"));
        assert!(cmd.contains("guava"));
        assert!(cmd.contains("32.1.3-jre"));
    }

    #[test]
    fn test_build_audit_script_uses_sentinel_not_install_mtime() {
        let script = build_audit_script("echo hi", true, true, true);
        assert!(script.contains("/tmp/pkg-guard-sentinel"));
        assert!(script.contains("-newer /tmp/pkg-guard-sentinel"));
        assert!(!script.contains("-newer /install"));
        // Do not scan entire /root (npm cache false positives)
        assert!(!script.contains("find /etc /root "));
        assert!(script.contains("/root/.ssh"));
    }

    #[test]
    fn test_is_critical_fs_finding() {
        assert!(is_critical_fs_finding("/root/.ssh/authorized_keys"));
        assert!(is_critical_fs_finding("/var/spool/cron/crontabs/root"));
        assert!(!is_critical_fs_finding("/etc/hosts"));
        assert!(!is_critical_fs_finding("/etc/ssl/certs/ca.pem"));
    }

    #[test]
    fn test_determine_status_fs_is_warn_not_block() {
        let typosquat = crate::data::TyposquatResult {
            is_suspicious: false,
            is_blocklisted: false,
            blocklist_source: None,
            similar_to: vec![],
            min_levenshtein_distance: Some(0),
            recommendation: "ok".to_string(),
        };
        let audit = ContainerAuditResult {
            install_success: true,
            suspicious_activity: SuspiciousActivity {
                network: false,
                filesystem: true,
                processes: false,
            },
            network_findings: vec![],
            filesystem_findings: vec!["/etc/hosts".to_string()],
            process_findings: vec![],
            error: None,
        };
        let mut warnings = Vec::new();
        let status = determine_status(&typosquat, Some(&audit), &mut warnings);
        assert!(matches!(status, AuditStatus::Warning));
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_determine_status_critical_fs_is_block() {
        let typosquat = crate::data::TyposquatResult {
            is_suspicious: false,
            is_blocklisted: false,
            blocklist_source: None,
            similar_to: vec![],
            min_levenshtein_distance: Some(0),
            recommendation: "ok".to_string(),
        };
        let audit = ContainerAuditResult {
            install_success: true,
            suspicious_activity: SuspiciousActivity {
                network: false,
                filesystem: true,
                processes: false,
            },
            network_findings: vec![],
            filesystem_findings: vec!["/root/.ssh/authorized_keys".to_string()],
            process_findings: vec![],
            error: None,
        };
        let mut warnings = Vec::new();
        let status = determine_status(&typosquat, Some(&audit), &mut warnings);
        assert!(matches!(status, AuditStatus::Blocked));
    }

    #[test]
    fn test_determine_status_network_is_block() {
        let typosquat = crate::data::TyposquatResult {
            is_suspicious: false,
            is_blocklisted: false,
            blocklist_source: None,
            similar_to: vec![],
            min_levenshtein_distance: Some(0),
            recommendation: "ok".to_string(),
        };
        let audit = ContainerAuditResult {
            install_success: true,
            suspicious_activity: SuspiciousActivity {
                network: true,
                filesystem: false,
                processes: false,
            },
            network_findings: vec!["pastebin.com".to_string()],
            process_findings: vec![],
            filesystem_findings: vec![],
            error: None,
        };
        let mut warnings = Vec::new();
        let status = determine_status(&typosquat, Some(&audit), &mut warnings);
        assert!(matches!(status, AuditStatus::Blocked));
    }
}
