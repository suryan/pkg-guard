use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// `path -> (status, body, delay_ms)`
pub(crate) type Routes = HashMap<String, (u16, String, u64)>;

/// Minimal HTTP/1.1 registry stub on 127.0.0.1; unknown paths return 404.
pub(crate) struct MockRegistry {
    pub base: String,
    pub hits: Arc<AtomicUsize>,
}

pub(crate) async fn serve(routes: Routes) -> MockRegistry {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let routes = Arc::new(routes);
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let routes = routes.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let req = String::from_utf8_lossy(&buf);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body, delay) =
                    routes.get(&path).cloned().unwrap_or((404, "{}".into(), 0));
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    MockRegistry { base, hits }
}

pub(crate) fn route(routes: &mut Routes, path: &str, body: &str) {
    routes.insert(path.into(), (200, body.into(), 0));
}

fn cfg(base: &str) -> Config {
    Config {
        budget: Duration::from_secs(5),
        max_nodes: 100,
        max_depth: 16,
        concurrency: 8,
        pypi_base: base.into(),
        npm_base: base.into(),
        cache_dir: None,
        cache_ttl: Duration::from_secs(3600),
    }
}

fn root(name: &str, version: Option<&str>) -> Vec<PackageRef> {
    vec![PackageRef {
        name: name.into(),
        version: version.map(Into::into),
    }]
}

fn names(exp: &Expansion) -> Vec<&str> {
    exp.packages.iter().map(|p| p.name.as_str()).collect()
}

#[tokio::test]
async fn npm_tree_resolves_aliases_ranges_and_flags_non_registry() {
    let mut r = Routes::new();
    route(
        &mut r,
        "/root/1.0.0",
        r#"{"version":"1.0.0","dependencies":{"a":"^1.0.0","b":"2.0.0","alias":"npm:real-pkg@3.1.4","gitdep":"github:user/repo"}}"#,
    );
    route(
        &mut r,
        "/a/latest",
        r#"{"version":"1.5.0","dependencies":{"c":"~0.1.0","b":"^2"}}"#,
    );
    route(&mut r, "/b/2.0.0", r#"{"version":"2.0.0"}"#);
    route(&mut r, "/real-pkg/3.1.4", r#"{"version":"3.1.4"}"#);
    route(&mut r, "/c/latest", r#"{"version":"0.1.2"}"#);
    let mock = serve(r).await;

    let exp = expand_with_config(
        Ecosystem::Npm,
        &root("root", Some("1.0.0")),
        &cfg(&mock.base),
    )
    .await
    .unwrap();

    let mut n = names(&exp);
    n.sort_unstable();
    assert_eq!(n, ["a", "b", "c", "gitdep", "real-pkg", "root"]);
    let b = exp.packages.iter().find(|p| p.name == "b").unwrap();
    assert_eq!(b.version.as_deref(), Some("2.0.0"));
    let a = exp.packages.iter().find(|p| p.name == "a").unwrap();
    assert_eq!(a.version, None);
    assert_eq!(exp.unresolved.len(), 1);
    assert!(exp.unresolved[0].contains("gitdep: non-registry spec github:user/repo"));
    assert_eq!(exp.limit_hit, None);
    assert!(!exp.is_complete());
    assert_eq!(exp.unversioned, 3); // a, c, gitdep
}

#[tokio::test]
async fn failed_lookup_is_reported_not_skipped() {
    let mut r = Routes::new();
    route(
        &mut r,
        "/root/1.0.0",
        r#"{"version":"1.0.0","dependencies":{"missing":"^1.0.0"}}"#,
    );
    let mock = serve(r).await;

    let exp = expand_with_config(
        Ecosystem::Npm,
        &root("root", Some("1.0.0")),
        &cfg(&mock.base),
    )
    .await
    .unwrap();

    assert!(names(&exp).contains(&"missing"));
    assert_eq!(exp.unresolved.len(), 1);
    assert!(
        exp.unresolved[0].starts_with("missing: 404"),
        "{:?}",
        exp.unresolved
    );
    assert!(!exp.is_complete());
}

#[tokio::test]
async fn budget_caps_wall_clock_on_slow_registry() {
    let mut r = Routes::new();
    let deps: Vec<String> = (0..5).map(|i| format!("\"slow{i}\":\"^1.0.0\"")).collect();
    route(
        &mut r,
        "/root/1.0.0",
        &format!(
            r#"{{"version":"1.0.0","dependencies":{{{}}}}}"#,
            deps.join(",")
        ),
    );
    for i in 0..5 {
        r.insert(
            format!("/slow{i}/latest"),
            (200, r#"{"version":"1.0.0"}"#.into(), 5_000),
        );
    }
    let mock = serve(r).await;
    let mut c = cfg(&mock.base);
    c.budget = Duration::from_millis(300);

    let start = Instant::now();
    let exp = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();

    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(exp.limit_hit, Some(LimitHit::Budget));
    assert_eq!(exp.unexpanded, 5);
    assert_eq!(exp.packages.len(), 6, "discovered names are still checked");
    assert!(!exp.is_complete());
}

#[tokio::test]
async fn fetches_run_concurrently() {
    let mut r = Routes::new();
    let deps: Vec<String> = (0..8).map(|i| format!("\"d{i}\":\"^1.0.0\"")).collect();
    route(
        &mut r,
        "/root/1.0.0",
        &format!(
            r#"{{"version":"1.0.0","dependencies":{{{}}}}}"#,
            deps.join(",")
        ),
    );
    for i in 0..8 {
        r.insert(
            format!("/d{i}/latest"),
            (200, r#"{"version":"1.0.0"}"#.into(), 400),
        );
    }
    let mock = serve(r).await;

    let start = Instant::now();
    let exp = expand_with_config(
        Ecosystem::Npm,
        &root("root", Some("1.0.0")),
        &cfg(&mock.base),
    )
    .await
    .unwrap();

    // Serial would take >= 8 * 400ms.
    assert!(
        start.elapsed() < Duration::from_millis(2_000),
        "{:?}",
        start.elapsed()
    );
    assert!(exp.is_complete(), "{exp:?}");
    assert_eq!(exp.packages.len(), 9);
}

#[tokio::test]
async fn node_and_depth_caps() {
    let mut r = Routes::new();
    route(
        &mut r,
        "/root/1.0.0",
        r#"{"version":"1.0.0","dependencies":{"a":"^1","b":"^1","c":"^1"}}"#,
    );
    route(
        &mut r,
        "/a/latest",
        r#"{"version":"1.0.0","dependencies":{"deep":"^1"}}"#,
    );
    route(&mut r, "/b/latest", r#"{"version":"1.0.0"}"#);
    route(&mut r, "/c/latest", r#"{"version":"1.0.0"}"#);
    let mock = serve(r).await;

    let mut c = cfg(&mock.base);
    c.max_nodes = 2;
    c.concurrency = 1;
    let exp = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert_eq!(exp.limit_hit, Some(LimitHit::MaxNodes));
    assert!(exp.unexpanded >= 2, "{exp:?}");

    let mut c = cfg(&mock.base);
    c.max_depth = 1;
    let exp = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert_eq!(exp.limit_hit, Some(LimitHit::MaxDepth));
    assert_eq!(exp.unexpanded, 3);
    assert!(!names(&exp).contains(&"deep"));
}

#[tokio::test]
async fn tag_root_resolves_to_concrete_version() {
    let mut r = Routes::new();
    route(&mut r, "/@scope/tool/latest", r#"{"version":"0.14.3"}"#);
    let mock = serve(r).await;

    let exp = expand_with_config(
        Ecosystem::Npm,
        &root("@scope/tool", Some("latest")),
        &cfg(&mock.base),
    )
    .await
    .unwrap();
    assert_eq!(exp.packages[0].version.as_deref(), Some("0.14.3"));
    assert!(exp.is_complete());
}

#[tokio::test]
async fn pypi_skips_extras_and_dedupes_normalized_names() {
    let mut r = Routes::new();
    route(
        &mut r,
        "/pypi/Root_Pkg/1.0/json",
        r#"{"info":{"version":"1.0","requires_dist":["Dep.One>=1","dep-one; python_version>'3'","extra-thing; extra == 'dev'"]}}"#,
    );
    route(
        &mut r,
        "/pypi/Dep.One/json",
        r#"{"info":{"version":"2.0","requires_dist":null}}"#,
    );
    let mock = serve(r).await;

    let exp = expand_with_config(
        Ecosystem::Python,
        &root("Root_Pkg", Some("1.0")),
        &cfg(&mock.base),
    )
    .await
    .unwrap();
    assert_eq!(names(&exp), ["Root_Pkg", "Dep.One"]);
    assert!(exp.is_complete(), "{exp:?}");
}

#[tokio::test]
async fn malformed_metadata_is_unresolved() {
    let mut r = Routes::new();
    route(&mut r, "/pypi/nover/json", r#"{"info":{}}"#);
    route(&mut r, "/pypi/noinfo/json", "{}");
    route(&mut r, "/badjson/latest", "not json");
    route(&mut r, "/npmnover/latest", "{}");
    let mock = serve(r).await;
    let c = cfg(&mock.base);

    for name in ["nover", "noinfo"] {
        let exp = expand_with_config(Ecosystem::Python, &root(name, None), &c)
            .await
            .unwrap();
        assert_eq!(exp.unresolved.len(), 1, "{name}");
    }
    for name in ["badjson", "npmnover"] {
        let exp = expand_with_config(Ecosystem::Npm, &root(name, None), &c)
            .await
            .unwrap();
        assert_eq!(exp.unresolved.len(), 1, "{name}");
    }
}

#[tokio::test]
async fn unreachable_registry_is_unresolved_quickly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);

    let exp = expand_with_config(Ecosystem::Npm, &root("x", None), &cfg(&base))
        .await
        .unwrap();
    assert_eq!(exp.unresolved.len(), 1);
    assert!(exp.unresolved[0].contains("request failed"));
}

#[tokio::test]
async fn disk_cache_serves_repeat_launches() {
    let dir = std::env::temp_dir().join(format!("pg-transitive-cache-{}", now_nanos()));
    let mut r = Routes::new();
    route(
        &mut r,
        "/root/1.0.0",
        r#"{"version":"1.0.0","dependencies":{"a":"^1"}}"#,
    );
    route(&mut r, "/a/latest", r#"{"version":"1.2.0"}"#);
    let mock = serve(r).await;
    let mut c = cfg(&mock.base);
    c.cache_dir = Some(dir.clone());

    let first = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert!(first.is_complete());
    assert_eq!(mock.hits.load(Ordering::SeqCst), 2);
    assert!(dir.join("npm.json").is_file());

    let second = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert!(second.is_complete());
    assert_eq!(names(&second), names(&first));
    assert_eq!(mock.hits.load(Ordering::SeqCst), 2, "served from cache");

    c.cache_ttl = Duration::ZERO;
    let _ = expand_with_config(Ecosystem::Npm, &root("root", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert_eq!(
        mock.hits.load(Ordering::SeqCst),
        4,
        "expired entries refetched"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn empty_and_cargo_passthrough() {
    let c = cfg("http://127.0.0.1:9");
    assert!(expand_with_config(Ecosystem::Python, &[], &c)
        .await
        .unwrap()
        .packages
        .is_empty());
    let exp = expand_with_config(Ecosystem::Cargo, &root("serde", Some("1.0.0")), &c)
        .await
        .unwrap();
    assert_eq!(exp.packages.len(), 1);
    assert!(exp.is_complete());
}

#[test]
fn npm_dep_specs() {
    let d = npm_dep("x", "1.2.3");
    assert_eq!(d.version.as_deref(), Some("1.2.3"));
    assert!(d.non_registry.is_none());
    assert_eq!(npm_dep("x", "^1.2.3").version, None);
    let d = npm_dep("x", "npm:@real/pkg@2.0.0");
    assert_eq!(d.name, "@real/pkg");
    assert_eq!(d.version.as_deref(), Some("2.0.0"));
    assert_eq!(npm_dep("x", "npm:@real/pkg").name, "@real/pkg");
    assert_eq!(npm_dep("x", "npm:other").name, "other");
    for spec in [
        "git+https://github.com/a/b.git",
        "user/repo",
        "file:../local",
        "workspace:*",
    ] {
        assert!(npm_dep("x", spec).non_registry.is_some(), "{spec}");
    }
}

#[test]
fn exact_semver_detection() {
    assert!(is_exact_semver("1.2.3"));
    assert!(is_exact_semver("1.2.3-beta.1"));
    assert!(is_exact_semver("1.2.3+build.5"));
    for s in [
        "1.x",
        "^1.2.3",
        "~1.2.3",
        "1.2",
        ">=1.0.0 <2",
        "latest",
        "*",
        "",
    ] {
        assert!(!is_exact_semver(s), "{s}");
    }
}

#[test]
fn test_pep508_name_and_normalize() {
    assert_eq!(
        pep508_name("requests>=2.0; python_version>=\"3\"").as_deref(),
        Some("requests")
    );
    assert_eq!(pep508_name("Foo[extra]==1.0").as_deref(), Some("Foo"));
    assert_eq!(pep508_name("").as_deref(), None);
    assert_eq!(pypi_normalize("Foo__Bar.baz"), "foo-bar-baz");
}

#[test]
#[serial_test::serial]
fn test_transitive_enabled_default() {
    std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
    assert!(transitive_enabled());
    std::env::set_var("PKG_GUARD_SHIM_TRANSITIVE", "0");
    assert!(!transitive_enabled());
    std::env::remove_var("PKG_GUARD_SHIM_TRANSITIVE");
}

#[test]
#[serial_test::serial]
fn config_from_env() {
    let c = Config::from_env();
    assert_eq!(c.budget, Duration::from_millis(DEFAULT_BUDGET_MS));
    assert!(c.cache_dir.is_some());

    std::env::set_var("PKG_GUARD_TRANSITIVE_BUDGET_MS", "1500");
    std::env::set_var("PKG_GUARD_TRANSITIVE_CONCURRENCY", "0");
    std::env::set_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS", "0");
    std::env::set_var("PKG_GUARD_NPM_REGISTRY", "http://mirror.local/npm/");
    let c = Config::from_env();
    assert_eq!(c.budget, Duration::from_millis(1500));
    assert_eq!(c.concurrency, 1);
    assert!(c.cache_dir.is_none());
    assert_eq!(c.npm_base, "http://mirror.local/npm");
    for k in [
        "PKG_GUARD_TRANSITIVE_BUDGET_MS",
        "PKG_GUARD_TRANSITIVE_CONCURRENCY",
        "PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS",
        "PKG_GUARD_NPM_REGISTRY",
    ] {
        std::env::remove_var(k);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_expand_pypi_requests_has_deps() {
    std::env::set_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS", "0");
    let exp = expand_with_transitive(Ecosystem::Python, &root("requests", Some("2.31.0")))
        .await
        .expect("pypi expand");
    std::env::remove_var("PKG_GUARD_TRANSITIVE_CACHE_TTL_SECS");
    assert!(
        exp.packages.len() > 1,
        "expected transitive deps, got {exp:?}"
    );
    assert!(exp.packages.iter().any(|p| {
        let n = p.name.to_ascii_lowercase();
        n == "urllib3" || n == "certifi" || n == "idna" || n == "charset-normalizer"
    }));
}
