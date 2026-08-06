use super::*;

#[test]
fn test_parse_requirements_pinned() {
    let content = "requests==2.31.0\nflask==3.0.0\n";
    let result = parse_requirements(content, "requirements.txt", false, false);
    assert_eq!(result.pinned_count, 2);
    assert_eq!(result.unpinned_count, 0);
}

#[test]
fn test_parse_requirements_unpinned() {
    let content = "requests>=2.0\nflask\nnumpy~=1.24\n";
    let result = parse_requirements(content, "requirements.txt", false, false);
    assert_eq!(result.unpinned_count, 3);
}

#[test]
fn test_parse_package_json_mixed() {
    let content = r#"{
        "dependencies": {
            "express": "4.18.2",
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "jest": "~29.7.0"
        }
    }"#;
    let result = parse_package_json(content, "package.json", false).expect("should parse");
    assert_eq!(result.pinned_count, 1);
    assert_eq!(result.unpinned_count, 2);
}

#[test]
fn test_scan_requirements_with_custom_blocklist() {
    let dir = std::env::temp_dir().join(format!("pg-scan-bl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let bl = dir.join("bl.json");
    std::fs::write(
        &bl,
        r#"{"python":["reqeusts"],"npm":[],"java":[],"cargo":[]}"#,
    )
    .expect("write");
    std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
    std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
    crate::data::custom_blocklist::reload();
    crate::data::feed_cache::reload();

    let content = "reqeusts==1.0.0\nflask==3.0.0\n";
    let findings = scan_requirements_as_lockfile(content);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].package, "reqeusts");

    let clean = "requests==2.31.0\nflask==3.0.0\n";
    assert!(scan_requirements_as_lockfile(clean).is_empty());

    std::env::remove_var("PKG_GUARD_BLOCKLIST");
    std::env::remove_var("PKG_GUARD_CACHE_DIR");
    crate::data::custom_blocklist::reload();
    crate::data::feed_cache::reload();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_parse_cargo_lock_entries() {
    let content = r#"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.40.0"
"#;
    let entries = parse_cargo_lock_entries(content);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, "serde");
    assert_eq!(entries[0].1, "1.0.200");
    assert_eq!(entries[1].0, "tokio");
}

#[test]
fn test_extract_xml_value() {
    assert_eq!(
        extract_xml_value("<artifactId>spring-core</artifactId>", "artifactId"),
        Some("spring-core".to_string())
    );
    assert_eq!(
        extract_xml_value("<version>5.3.20</version>", "version"),
        Some("5.3.20".to_string())
    );
    assert_eq!(extract_xml_value("<other>val</other>", "version"), None);
}

#[test]
fn test_format_scan_scope() {
    assert!(format_scan_scope(0, 0, None).contains("0 packages"));
    assert!(format_scan_scope(10, 0, None).contains("blocklist only"));
    assert!(format_scan_scope(100, 80, Some(80)).contains("cap 80"));
    assert!(format_scan_scope(5, 5, Some(80)).contains("OSV-checked 5"));
}
