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
    let (image, cmd) = get_install_config(Ecosystem::Java, "com.google.guava:guava", "32.1.3-jre");
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

fn clean_typosquat() -> crate::data::TyposquatResult {
    crate::data::TyposquatResult {
        is_suspicious: false,
        is_blocklisted: false,
        blocklist_source: None,
        similar_to: vec![],
        min_levenshtein_distance: Some(0),
        recommendation: "ok".to_string(),
    }
}

#[test]
fn test_determine_status_processes_and_install_fail() {
    let audit = ContainerAuditResult {
        install_success: false,
        suspicious_activity: SuspiciousActivity {
            network: false,
            filesystem: false,
            processes: true,
        },
        network_findings: vec![],
        filesystem_findings: vec![],
        process_findings: vec!["xmrig".into()],
        error: None,
    };
    let mut warnings = Vec::new();
    let status = determine_status(&clean_typosquat(), Some(&audit), &mut warnings);
    assert!(matches!(status, AuditStatus::Blocked));
    assert!(warnings.iter().any(|w| w.contains("process")));
}

#[test]
fn test_determine_status_container_error_and_typosquat() {
    let mut ts = clean_typosquat();
    ts.is_suspicious = true;
    ts.similar_to = vec!["requests".into()];
    let audit = ContainerAuditResult {
        install_success: false,
        suspicious_activity: SuspiciousActivity {
            network: false,
            filesystem: false,
            processes: false,
        },
        network_findings: vec![],
        filesystem_findings: vec![],
        process_findings: vec![],
        error: Some("docker gone".into()),
    };
    let mut warnings = vec!["prior".into()];
    let status = determine_status(&ts, Some(&audit), &mut warnings);
    assert!(matches!(status, AuditStatus::Warning));
    assert!(warnings.iter().any(|w| w.contains("Typosquat")));
}

#[test]
fn test_elevate_and_osv_helpers() {
    assert!(matches!(
        elevate(AuditStatus::Pass, AuditStatus::Warning),
        AuditStatus::Warning
    ));
    assert!(matches!(
        elevate(AuditStatus::Blocked, AuditStatus::Warning),
        AuditStatus::Blocked
    ));
    assert!(matches!(
        elevate(AuditStatus::Pass, AuditStatus::Failed),
        AuditStatus::Failed
    ));

    let mut osv = osv::OsvQueryResult {
        package: "p".into(),
        version: "1".into(),
        ecosystem: "PyPI".into(),
        advisories: vec![osv::OsvAdvisory {
            id: "MAL-9".into(),
            summary: "bad".into(),
            severity: "CRITICAL".into(),
            is_malware: true,
            package: "p".into(),
            version: "1".into(),
            ecosystem: "PyPI".into(),
            details_url: None,
        }],
        error: None,
    };
    assert!(matches!(
        elevate_with_osv(AuditStatus::Pass, Some(&osv)),
        AuditStatus::Blocked
    ));
    osv.advisories[0].is_malware = false;
    osv.advisories[0].severity = "HIGH".into();
    assert!(matches!(
        elevate_with_osv(AuditStatus::Pass, Some(&osv)),
        AuditStatus::Blocked
    ));
    osv.advisories[0].severity = "LOW".into();
    assert!(matches!(
        elevate_with_osv(AuditStatus::Pass, Some(&osv)),
        AuditStatus::Warning
    ));
    osv.advisories.clear();
    assert!(matches!(
        elevate_with_osv(AuditStatus::Pass, Some(&osv)),
        AuditStatus::Pass
    ));
    assert!(matches!(
        elevate_with_osv(AuditStatus::Warning, None),
        AuditStatus::Warning
    ));

    let mut warnings = Vec::new();
    apply_osv_warnings(None, &mut warnings);
    assert!(warnings.is_empty());
    apply_osv_warnings(
        Some(&osv::OsvQueryResult {
            package: "p".into(),
            version: "1".into(),
            ecosystem: "PyPI".into(),
            advisories: vec![],
            error: Some("net".into()),
        }),
        &mut warnings,
    );
    assert!(warnings[0].contains("OSV"));
    warnings.clear();
    apply_osv_warnings(
        Some(&osv::OsvQueryResult {
            package: "p".into(),
            version: "1".into(),
            ecosystem: "PyPI".into(),
            advisories: vec![osv::OsvAdvisory {
                id: "GHSA-1".into(),
                summary: "cve".into(),
                severity: "MEDIUM".into(),
                is_malware: false,
                package: "p".into(),
                version: "1".into(),
                ecosystem: "PyPI".into(),
                details_url: None,
            }],
            error: None,
        }),
        &mut warnings,
    );
    assert!(warnings[0].contains("advisory"));
}

#[test]
fn test_collect_metadata_warnings_npm_scripts() {
    let meta = serde_json::json!({"has_install_scripts": true});
    let w = collect_metadata_warnings(Ecosystem::Npm, Some(&meta));
    assert!(w.iter().any(|s| s.contains("install-time")));
    assert!(collect_metadata_warnings(Ecosystem::Python, Some(&meta)).is_empty());
    assert!(collect_metadata_warnings(Ecosystem::Npm, None).is_empty());
}

#[test]
fn test_parse_audit_output_fallback_and_mixed() {
    let r = parse_audit_output("no json here", 1);
    assert!(!r.install_success);
    assert!(r.error.is_some());
    let r = parse_audit_output("noise {not-json} more", 0);
    // may fall back if unparseable
    let _ = r.install_success;
    let mixed = r#"log
{"install_success":false,"suspicious_activity":{"network":true,"filesystem":false,"processes":false},"network_findings":["x"],"filesystem_findings":[],"process_findings":[]}
"#;
    let r = parse_audit_output(mixed, 0);
    assert!(!r.install_success);
    assert!(r.suspicious_activity.network);
}

#[test]
fn test_get_install_config_java_without_colon() {
    let (img, cmd) = get_install_config(Ecosystem::Java, "orphan-artifact", "1.0");
    assert!(img.contains("maven"));
    assert!(cmd.contains("orphan-artifact"));
}

#[test]
fn test_build_audit_script_flags_off() {
    let s = build_audit_script("true", false, false, false);
    assert!(s.contains("pkg-guard-sentinel"));
    assert!(s.contains("false"));
}
