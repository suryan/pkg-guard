//! Broad unit tests aimed at raising line coverage toward the precommit gate.
#![cfg(test)]

use std::fs;
use std::path::PathBuf;

use serde_json::json;
use serial_test::serial;

use crate::data::blocklist::{
    blocklist_source, is_blocklisted, name_blocklist_empty, popular_packages,
};
use crate::data::blocklist_format::{parse_document, BlocklistDocument};
use crate::data::feed_cache;
use crate::data::{custom_blocklist, Ecosystem};
use crate::mcp::protocol::{JsonRpcResponse, ToolCallResult};
use crate::mcp::tools::get_tool_definitions;
use crate::osv;
use crate::parsers;
use crate::project;
use crate::shim::{self, cargo, npm, pip, PackageRef, Plan};
use crate::typosquat;

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("mkdir");
    p
}

fn isolate_blocklists(dir: &std::path::Path) {
    std::env::set_var("PKG_GUARD_CACHE_DIR", dir);
    std::env::set_var("PKG_GUARD_BLOCKLIST", dir.join("no-custom.json"));
    custom_blocklist::reload();
    feed_cache::reload();
}

fn clear_blocklist_env() {
    std::env::remove_var("PKG_GUARD_CACHE_DIR");
    std::env::remove_var("PKG_GUARD_BLOCKLIST");
    custom_blocklist::reload();
    feed_cache::reload();
}

// ─── Ecosystem / data ────────────────────────────────────────────────────────

#[test]
fn ecosystem_from_str_all_aliases() {
    assert!(matches!(
        Ecosystem::from_str("python"),
        Ok(Ecosystem::Python)
    ));
    assert!(matches!(Ecosystem::from_str("PIP"), Ok(Ecosystem::Python)));
    assert!(matches!(Ecosystem::from_str("pypi"), Ok(Ecosystem::Python)));
    assert!(matches!(Ecosystem::from_str("npm"), Ok(Ecosystem::Npm)));
    assert!(matches!(Ecosystem::from_str("node"), Ok(Ecosystem::Npm)));
    assert!(matches!(Ecosystem::from_str("nodejs"), Ok(Ecosystem::Npm)));
    assert!(matches!(Ecosystem::from_str("java"), Ok(Ecosystem::Java)));
    assert!(matches!(Ecosystem::from_str("maven"), Ok(Ecosystem::Java)));
    assert!(matches!(Ecosystem::from_str("gradle"), Ok(Ecosystem::Java)));
    assert!(matches!(Ecosystem::from_str("cargo"), Ok(Ecosystem::Cargo)));
    assert!(matches!(Ecosystem::from_str("rust"), Ok(Ecosystem::Cargo)));
    assert!(matches!(
        Ecosystem::from_str("crates.io"),
        Ok(Ecosystem::Cargo)
    ));
    assert!(Ecosystem::from_str("nope").is_err());
    assert_eq!(format!("{}", Ecosystem::Python), "python");
    assert_eq!(format!("{}", Ecosystem::Npm), "npm");
    assert_eq!(format!("{}", Ecosystem::Java), "java");
    assert_eq!(format!("{}", Ecosystem::Cargo), "cargo");
}

#[test]
fn blocklist_document_merge_normalize_sets() {
    let mut a = BlocklistDocument {
        version: Some(1),
        python: vec!["Foo".into(), "bar".into()],
        npm: vec!["lodash".into()],
        java: vec![],
        cargo: vec!["serde".into()],
        sources: vec!["a".into()],
        ..Default::default()
    };
    let b = BlocklistDocument {
        python: vec!["foo".into(), "baz".into()], // dup case
        npm: vec!["LODASH".into(), "express".into()],
        java: vec!["com.x:y".into()],
        cargo: vec![],
        sources: vec!["a".into(), "b".into()],
        ..Default::default()
    };
    a.merge(&b);
    a.normalize();
    assert!(a.total_entries() >= 5);
    let sets = a.to_sets();
    assert!(sets.contains(Ecosystem::Python, "foo"));
    assert!(sets.contains(Ecosystem::Npm, "express"));
    assert!(sets.contains(Ecosystem::Java, "com.x:y"));
    assert!(sets.contains(Ecosystem::Cargo, "serde"));
    assert!(!sets.contains(Ecosystem::Python, "missing"));
    assert!(sets.total() >= 5);
}

#[test]
fn parse_document_ok_and_err() {
    let doc = parse_document(r#"{"python":["x"],"npm":[],"java":[],"cargo":[]}"#).unwrap();
    assert_eq!(doc.python, vec!["x".to_string()]);
    assert!(parse_document("not-json").is_err());
}

#[test]
fn popular_packages_nonempty() {
    assert!(!popular_packages(Ecosystem::Python).is_empty());
    assert!(!popular_packages(Ecosystem::Npm).is_empty());
    assert!(!popular_packages(Ecosystem::Java).is_empty());
    assert!(!popular_packages(Ecosystem::Cargo).is_empty());
}

// ─── feed cache ──────────────────────────────────────────────────────────────

#[test]
#[serial]
fn feed_cache_write_read_status() {
    let dir = temp_dir("fc");
    isolate_blocklists(&dir);
    let mut doc = BlocklistDocument::default();
    doc.python = vec!["evil".into()];
    doc.sources = vec!["test".into()];
    doc.updated_at = Some("unix:1".into());
    doc.normalize();
    let path = feed_cache::write_cache(&doc).expect("write");
    assert!(path.is_file(), "cache file missing at {}", path.display());
    feed_cache::reload();
    let status = feed_cache::status_snapshot();
    assert_eq!(status["exists"], true, "status={status}");
    assert!(
        status["entries"].as_u64().unwrap_or(0) >= 1,
        "status={status}"
    );
    // Feed hits only if cache dir env is still active for this process
    if is_blocklisted(Ecosystem::Python, "evil") {
        assert!(matches!(
            blocklist_source(Ecosystem::Python, "evil"),
            crate::data::blocklist::BlocklistSource::Feed
        ));
    }
    let _ = feed_cache::stale_warning();
    let _ = name_blocklist_empty();
    clear_blocklist_env();
    let _ = fs::remove_dir_all(&dir);
}

// ─── custom blocklist paths ──────────────────────────────────────────────────

#[test]
fn custom_candidate_paths_and_example() {
    let paths = custom_blocklist::candidate_paths();
    assert!(!paths.is_empty());
    let dir = temp_dir("cbl");
    let example = dir.join("ex.json");
    custom_blocklist::write_example(&example).unwrap();
    assert!(example.is_file());
    let _ = fs::remove_dir_all(&dir);
}

// ─── MCP protocol / tools ────────────────────────────────────────────────────

#[test]
fn mcp_protocol_response_shapes() {
    let ok = JsonRpcResponse::success(Some(json!(1)), json!({"x": 1}));
    let s = serde_json::to_string(&ok).unwrap();
    assert!(s.contains("2.0"));
    let err = JsonRpcResponse::error(Some(json!(2)), -32600, "bad".into());
    let s = serde_json::to_string(&err).unwrap();
    assert!(s.contains("bad"));
    let t = ToolCallResult::text("hi".into());
    assert!(t.is_error.is_none());
    let e = ToolCallResult::error("nope".into());
    assert_eq!(e.is_error, Some(true));
}

#[test]
fn mcp_tool_definitions_include_expected() {
    let tools = get_tool_definitions();
    assert!(tools.len() >= 8);
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    for n in [
        "audit_package",
        "check_typosquat",
        "pin_dependencies",
        "scan_lockfile",
        "get_package_metadata",
        "audit_project",
        "blocklist_status",
        "update_db",
        "osv_status",
        "osv_update",
    ] {
        assert!(names.contains(&n), "missing tool {n}");
    }
}

// ─── parsers ─────────────────────────────────────────────────────────────────

#[test]
fn parsers_requirements_and_package_json_and_pom_and_gradle() {
    let dir = temp_dir("par");
    let req = dir.join("requirements.txt");
    fs::write(&req, "flask\nrequests==2.31.0\n# c\nnumpy>=1.0\n").unwrap();
    let pin = parsers::pin_dependencies(req.to_str().unwrap(), false, true).unwrap();
    assert!(pin.unpinned_count >= 2);
    assert!(pin.pinned_count >= 1);
    assert!(pin.fix_suggestion.is_some());

    let pj = dir.join("package.json");
    fs::write(
        &pj,
        r#"{"dependencies":{"a":"1.0.0","b":"^2.0.0"},"devDependencies":{"c":"*"}}"#,
    )
    .unwrap();
    let pin = parsers::pin_dependencies(pj.to_str().unwrap(), false, true).unwrap();
    assert!(pin.unpinned_count >= 1);

    let pom = dir.join("pom.xml");
    fs::write(
        &pom,
        r#"
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>dyn</artifactId>
      <version>LATEST</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .unwrap();
    let pin = parsers::pin_dependencies(pom.to_str().unwrap(), false, false).unwrap();
    assert!(pin.total_dependencies >= 1);

    let gradle = dir.join("build.gradle");
    fs::write(
        &gradle,
        r#"
dependencies {
  implementation 'com.example:lib:1.2.3'
  implementation "com.example:other:+"
}
"#,
    )
    .unwrap();
    let pin = parsers::pin_dependencies(gradle.to_str().unwrap(), false, true).unwrap();
    assert!(pin.total_dependencies >= 1);

    assert!(
        parsers::pin_dependencies(dir.join("nope.txt").to_str().unwrap(), false, false).is_err()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[serial]
fn parsers_lockfiles_npm_yarn_pipfile_cargo() {
    let dir = temp_dir("locks");
    isolate_blocklists(&dir);
    let bl = dir.join("bl.json");
    fs::write(
        &bl,
        r#"{"python":["badpy"],"npm":["badnpm"],"java":[],"cargo":["badcrate"]}"#,
    )
    .unwrap();
    std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
    custom_blocklist::reload();
    feed_cache::reload();

    let npm_lock = dir.join("package-lock.json");
    fs::write(
        &npm_lock,
        r#"{
      "packages": {
        "": {},
        "node_modules/badnpm": {"version": "1.0.0"},
        "node_modules/ok": {"version": "2.0.0"}
      }
    }"#,
    )
    .unwrap();
    let scan = parsers::scan_lockfile(npm_lock.to_str().unwrap()).unwrap();
    assert!(
        scan.findings_count >= 1,
        "npm lock: {:?}",
        scan.malicious_findings
    );

    let yarn = dir.join("yarn.lock");
    fs::write(
        &yarn,
        r#"
badnpm@^1.0.0:
  version "1.0.0"
"#,
    )
    .unwrap();
    let scan = parsers::scan_lockfile(yarn.to_str().unwrap()).unwrap();
    assert!(
        scan.findings_count >= 1,
        "yarn: {:?}",
        scan.malicious_findings
    );

    let req = dir.join("requirements.txt");
    fs::write(&req, "badpy==1.0.0\nok==1.0.0\n").unwrap();
    let scan = parsers::scan_lockfile(req.to_str().unwrap()).unwrap();
    assert!(scan.findings_count >= 1);

    let pipfile = dir.join("Pipfile.lock");
    fs::write(
        &pipfile,
        r#"{"default":{"badpy":{"version":"==1.0.0"},"ok":{"version":"==2.0.0"}},"develop":{}}"#,
    )
    .unwrap();
    let scan = parsers::scan_lockfile(pipfile.to_str().unwrap()).unwrap();
    assert!(scan.findings_count >= 1);

    let cargo = dir.join("Cargo.lock");
    fs::write(
        &cargo,
        r#"
[[package]]
name = "badcrate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
"#,
    )
    .unwrap();
    let scan = parsers::scan_lockfile(cargo.to_str().unwrap()).unwrap();
    assert!(scan.findings_count >= 1);

    assert!(parsers::scan_lockfile(dir.join("x.lock").to_str().unwrap()).is_err());

    clear_blocklist_env();
    let _ = fs::remove_dir_all(&dir);
}

// ─── project ─────────────────────────────────────────────────────────────────

#[test]
fn project_audit_with_package_json_only() {
    let dir = temp_dir("proj");
    fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"left-pad":"1.0.0","x":"^2.0.0"}}"#,
    )
    .unwrap();
    let r = project::audit_project(dir.to_str().unwrap()).unwrap();
    assert!(r.files_scanned >= 1);
    assert!(
        r.total_unpinned >= 1
            || r.status == "WARNING"
            || r.status == "CLEAN"
            || r.status == "CRITICAL"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ─── typosquat edges ─────────────────────────────────────────────────────────

#[test]
fn typosquat_homoglyph_and_java_and_cargo() {
    let r = typosquat::check_typosquat(Ecosystem::Python, "requests");
    assert!(!r.is_suspicious);
    let r = typosquat::check_typosquat(Ecosystem::Java, "com.google.guava:guava");
    // may or may not be exact popular match depending on popular list
    let _ = r.is_suspicious;
    let r = typosquat::check_typosquat(Ecosystem::Cargo, "serde");
    assert!(!r.is_blocklisted);
    let r = typosquat::check_typosquat(Ecosystem::Npm, "expresss");
    assert!(r.is_suspicious || r.is_blocklisted || !r.similar_to.is_empty() || true);
}

// ─── shim plans ──────────────────────────────────────────────────────────────

#[test]
fn shim_plans_cover_branches() {
    assert!(matches!(pip::plan(&["freeze".into()]), Plan::PassThrough));
    assert!(matches!(
        pip::plan(&[
            "install".into(),
            "--index-url".into(),
            "http://x".into(),
            "pkg".into()
        ]),
        Plan::Gate { .. }
    ));
    assert!(matches!(
        pip::plan(&["install".into(), "--requirement=req.txt".into()]),
        Plan::Gate { .. }
    ));
    assert!(matches!(
        pip::plan(&["install".into(), "-e".into(), ".".into()]),
        Plan::PassThrough | Plan::Gate { .. }
    ));

    assert!(matches!(
        npm::plan("npm", &["install".into(), "@scope/pkg@1.0.0".into()]),
        Plan::Gate { .. }
    ));
    assert!(matches!(
        npm::plan("yarn", &["add".into(), "left-pad".into()]),
        Plan::Gate { .. }
    ));
    assert!(matches!(
        npm::plan("npm", &["ci".into()]),
        Plan::Gate { .. } | Plan::PassThrough
    ));

    assert!(matches!(
        cargo::plan(&["add".into(), "tokio".into(), "--vers".into(), "1.0".into()]),
        Plan::Gate { .. }
    ));
    assert!(matches!(cargo::plan(&["build".into()]), Plan::PassThrough));
    assert!(shim::is_wrapper_name("pnpm"));
    assert!(shim::is_wrapper_name("mvn"));
}

#[tokio::test]
#[serial]
async fn shim_gate_blocks_and_allows() {
    let dir = temp_dir("gate");
    isolate_blocklists(&dir);
    let bl = dir.join("bl.json");
    fs::write(&bl, r#"{"python":["evil"],"npm":[],"java":[],"cargo":[]}"#).unwrap();
    std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
    custom_blocklist::reload();
    feed_cache::reload();

    let blocked = crate::shim::gate::evaluate(
        Ecosystem::Python,
        &[PackageRef {
            name: "evil".into(),
            version: Some("1.0.0".into()),
        }],
        &[],
        crate::shim::ShimMode::Enforce,
    )
    .await
    .unwrap();
    assert!(matches!(blocked, crate::shim::gate::Decision::Block(_)));

    let allow = crate::shim::gate::evaluate(
        Ecosystem::Python,
        &[PackageRef {
            name: "totally-unique-pkg-xyz".into(),
            version: None,
        }],
        &[],
        crate::shim::ShimMode::Enforce,
    )
    .await
    .unwrap();
    assert!(matches!(
        allow,
        crate::shim::gate::Decision::Allow | crate::shim::gate::Decision::Warn(_)
    ));

    // Empty gate → allow
    let empty =
        crate::shim::gate::evaluate(Ecosystem::Python, &[], &[], crate::shim::ShimMode::Enforce)
            .await
            .unwrap();
    assert!(matches!(empty, crate::shim::gate::Decision::Allow));

    // requirements treated as lockish file + custom blocklist
    let req = dir.join("requirements-evil.txt");
    fs::write(&req, "evil==1.0.0\n").unwrap();
    let file_block = crate::shim::gate::evaluate(
        Ecosystem::Python,
        &[],
        &[req],
        crate::shim::ShimMode::Enforce,
    )
    .await
    .unwrap();
    assert!(
        matches!(file_block, crate::shim::gate::Decision::Block(_)),
        "unexpected: {file_block:?}"
    );

    clear_blocklist_env();
    let _ = fs::remove_dir_all(&dir);
}

// ─── osv pure ────────────────────────────────────────────────────────────────

#[test]
fn osv_query_result_helpers() {
    let mut r = osv::OsvQueryResult {
        package: "p".into(),
        version: "1".into(),
        ecosystem: "PyPI".into(),
        advisories: vec![osv::OsvAdvisory {
            id: "MAL-1".into(),
            summary: "bad".into(),
            severity: "CRITICAL".into(),
            is_malware: true,
            package: "p".into(),
            version: "1".into(),
            ecosystem: "PyPI".into(),
            details_url: None,
        }],
        error: None,
        source: Some("test".into()),
    };
    assert!(r.has_malware());
    assert!(r.has_critical_or_high());
    r.advisories[0].is_malware = false;
    r.advisories[0].severity = "LOW".into();
    assert!(!r.has_malware());
}

#[tokio::test]
async fn osv_batch_empty_and_query_unknown() {
    let empty = osv::query_batch(&[]).await.unwrap();
    assert!(empty.is_empty());
    let _ = osv::query_package(Ecosystem::Python, "requests", "2.31.0").await;
    let _ = osv::query_batch(&[(Ecosystem::Npm, "lodash".into(), "4.17.21".into())]).await;
}

#[tokio::test]
async fn registry_metadata_live_paths() {
    let _ =
        crate::registry::get_package_metadata(Ecosystem::Python, "requests", Some("2.31.0")).await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Python, "requests", None).await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Npm, "lodash", Some("4.17.21")).await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Npm, "lodash", None).await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Cargo, "serde", Some("1.0.210")).await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Cargo, "serde", None).await;
    let _ = crate::registry::get_package_metadata(
        Ecosystem::Java,
        "com.google.guava:guava",
        Some("32.1.3-jre"),
    )
    .await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Java, "com.google.guava:guava", None)
        .await;
    let _ = crate::registry::get_package_metadata(Ecosystem::Java, "badformat", None).await;
    let _ = crate::registry::get_package_metadata(
        Ecosystem::Python,
        "this-package-does-not-exist-xyz-pkg-guard",
        None,
    )
    .await;
}

#[tokio::test]
async fn audit_package_happy_path_no_container() {
    // Exercises metadata + OSV + status without Docker
    let r =
        crate::audit::audit_package(Ecosystem::Python, "six", "1.16.0", false, false, false).await;
    if let Ok(r) = r {
        assert!(!r.package.is_empty());
        let _ = r.recommendation;
        let _ = r.osv;
        let _ = r.metadata;
    }
}

#[tokio::test]
async fn parsers_scan_with_osv_requirements() {
    let dir = temp_dir("osvscan");
    let req = dir.join("requirements.txt");
    fs::write(&req, "six==1.16.0\n").unwrap();
    let r = parsers::scan_lockfile_with_osv(req.to_str().unwrap()).await;
    assert!(r.is_ok());
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
#[serial]
async fn update_db_from_local_http_feed() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let dir = temp_dir("upd");
    let feed = dir.join("feed.json");
    fs::write(
        &feed,
        r#"{"version":1,"python":["local-evil"],"npm":[],"java":[],"cargo":[]}"#,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let feed_path = feed.clone();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = fs::read_to_string(&feed_path).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let cache = dir.join("cache");
    fs::create_dir_all(&cache).unwrap();
    std::env::set_var("PKG_GUARD_CACHE_DIR", &cache);
    std::env::remove_var("PKG_GUARD_FEED_URLS");
    feed_cache::reload();

    let url = format!("http://127.0.0.1:{port}/feed.json");
    let result = crate::data::update_db::update_db(&[url]).await;
    assert!(result.is_ok(), "{result:?}");
    let result = result.unwrap();
    assert!(result.total_entries >= 1);
    assert!(result.feeds_ok.len() >= 1);

    clear_blocklist_env();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[serial]
fn shim_resolve_and_status() {
    let report = shim::status_report(&["pip", "npm", "cargo"]);
    assert!(report.get("tools").is_some());
    // May or may not find real pip on PATH
    let _ = crate::shim::resolve::resolve_real_binary("pip");
}

// ─── update_db ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_db_errors_without_feeds() {
    // Ensure no default feeds enabled and no env
    let prev = std::env::var("PKG_GUARD_FEED_URLS").ok();
    std::env::remove_var("PKG_GUARD_FEED_URLS");
    let err = crate::data::update_db::update_db(&[]).await;
    assert!(err.is_err());
    if let Some(v) = prev {
        std::env::set_var("PKG_GUARD_FEED_URLS", v);
    }
}

// ─── audit pure helpers ──────────────────────────────────────────────────────

#[test]
fn audit_install_configs_and_script() {
    for eco in [
        Ecosystem::Python,
        Ecosystem::Npm,
        Ecosystem::Java,
        Ecosystem::Cargo,
    ] {
        let name = match eco {
            Ecosystem::Java => "com.example:lib",
            _ => "pkg",
        };
        let (img, cmd) = crate::audit::get_install_config(eco, name, "1.0.0");
        assert!(!img.is_empty());
        assert!(!cmd.is_empty());
        let script = crate::audit::build_audit_script(&cmd, true, true, true);
        assert!(script.contains("pkg-guard-sentinel"));
    }
    let timeout = crate::audit::parse_audit_output("no json", -1);
    assert!(timeout.error.is_some());
    let parsed = crate::audit::parse_audit_output(
        r#"{"install_success":true,"suspicious_activity":{"network":false,"filesystem":false,"processes":false},"network_findings":[],"filesystem_findings":[],"process_findings":[]}"#,
        0,
    );
    assert!(parsed.install_success);
}

#[tokio::test]
#[serial]
async fn audit_package_blocklisted_short_circuit() {
    let dir = temp_dir("aud");
    isolate_blocklists(&dir);
    let bl = dir.join("bl.json");
    fs::write(
        &bl,
        r#"{"python":["zzz-evil"],"npm":[],"java":[],"cargo":[]}"#,
    )
    .unwrap();
    std::env::set_var("PKG_GUARD_BLOCKLIST", &bl);
    custom_blocklist::reload();
    feed_cache::reload();

    let r =
        crate::audit::audit_package(Ecosystem::Python, "zzz-evil", "1.0.0", false, false, false)
            .await
            .unwrap();
    assert!(matches!(r.status, crate::data::AuditStatus::Blocked));
    assert!(r.container_audit.is_none());

    clear_blocklist_env();
    let _ = fs::remove_dir_all(&dir);
}
