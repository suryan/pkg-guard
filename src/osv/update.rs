//! Download OSV ecosystem dumps and build local package indexes.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use super::local::{
    clear_memory_cache, save_index, save_meta, EcoMeta, EcosystemIndex, IndexedAdvisory,
    IndexedRange, OsvMeta,
};
use super::{map_severity_from_raw, osv_ecosystem, OsvSeverity, OsvVulnLike};
use crate::data::Ecosystem;

const DEFAULT_DUMP_BASE: &str = "https://storage.googleapis.com/osv-vulnerabilities";

/// Result of `osv update`.
#[derive(Debug, serde::Serialize)]
pub struct OsvUpdateResult {
    pub osv_dir: String,
    pub updated_at: String,
    pub ecosystems: Vec<EcoUpdateRow>,
    pub message: String,
}

/// Per-ecosystem update row.
#[derive(Debug, serde::Serialize)]
pub struct EcoUpdateRow {
    pub ecosystem: String,
    pub advisory_count: usize,
    pub package_count: usize,
    pub ok: bool,
    pub error: Option<String>,
}

/// Ecosystems we download by default.
pub fn default_ecosystems() -> Vec<Ecosystem> {
    vec![
        Ecosystem::Python,
        Ecosystem::Npm,
        Ecosystem::Java,
        Ecosystem::Cargo,
    ]
}

/// Base URL for OSV ecosystem zips (override with `PKG_GUARD_OSV_DUMP_BASE` for tests/mirrors).
fn dump_base() -> String {
    std::env::var("PKG_GUARD_OSV_DUMP_BASE").unwrap_or_else(|_| DEFAULT_DUMP_BASE.to_string())
}

fn dump_url(osv_eco: &str) -> String {
    // URL-encode is not needed for known ecosystem names; crates.io has a dot.
    format!("{}/{osv_eco}/all.zip", dump_base().trim_end_matches('/'))
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .user_agent(concat!("pkg-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to create HTTP client for OSV dump download")
}

/// Download dumps for the given ecosystems (or defaults) and rebuild indexes.
pub async fn update_osv(ecosystems: &[Ecosystem]) -> Result<OsvUpdateResult> {
    let ecos: Vec<Ecosystem> = if ecosystems.is_empty() {
        default_ecosystems()
    } else {
        ecosystems.to_vec()
    };

    let client = http_client()?;
    let mut rows = Vec::new();
    let mut meta = OsvMeta {
        updated_at: None,
        ecosystems: HashMap::new(),
        source: dump_base(),
    };

    let total_steps = ecos.len();
    eprintln!(
        "pkg-guard osv update: {} ecosystem(s) → {}",
        total_steps,
        super::local::osv_dir().display()
    );

    for (i, eco) in ecos.iter().enumerate() {
        let osv_name = osv_ecosystem(*eco);
        let step = i + 1;
        eprintln!("[{step}/{total_steps}] {osv_name}");
        match update_one(&client, osv_name).await {
            Ok(index) => {
                info!(
                    "OSV index {osv_name}: {} advisories across {} packages",
                    index.advisory_count, index.package_count
                );
                eprintln!(
                    "  ✓ indexed {} advisories / {} packages",
                    index.advisory_count, index.package_count
                );
                rows.push(EcoUpdateRow {
                    ecosystem: osv_name.to_string(),
                    advisory_count: index.advisory_count,
                    package_count: index.package_count,
                    ok: true,
                    error: None,
                });
                meta.ecosystems.insert(
                    osv_name.to_string(),
                    EcoMeta {
                        advisory_count: index.advisory_count,
                        package_count: index.package_count,
                        updated_at: Some(unix_now()),
                    },
                );
            }
            Err(e) => {
                warn!("OSV update failed for {osv_name}: {e}");
                eprintln!("  ✗ failed: {e}");
                rows.push(EcoUpdateRow {
                    ecosystem: osv_name.to_string(),
                    advisory_count: 0,
                    package_count: 0,
                    ok: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let ok_count = rows.iter().filter(|r| r.ok).count();
    if ok_count == 0 {
        bail!(
            "All OSV dump downloads failed: {}",
            rows.iter()
                .filter_map(|r| r.error.as_deref())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    meta.updated_at = Some(unix_now());
    save_meta(&meta)?;
    clear_memory_cache();

    let dir = super::local::osv_dir();
    Ok(OsvUpdateResult {
        osv_dir: dir.display().to_string(),
        updated_at: meta.updated_at.clone().unwrap_or_default(),
        ecosystems: rows,
        message: format!(
            "Updated local OSV index for {ok_count}/{} ecosystem(s). \
             scan/audit will use local dumps (PKG_GUARD_OSV_MODE=auto|local).",
            ecos.len()
        ),
    })
}

async fn update_one(client: &reqwest::Client, osv_eco: &str) -> Result<EcosystemIndex> {
    let url = dump_url(osv_eco);
    info!("Downloading OSV dump {url}");
    let started = Instant::now();

    let bytes = download_with_progress(client, &url, osv_eco).await?;
    info!(
        "Downloaded {osv_eco} dump ({} bytes) in {:.1}s",
        bytes.len(),
        started.elapsed().as_secs_f64()
    );

    eprint!("  indexing {osv_eco}…");
    let _ = std::io::stderr().flush();
    let index_started = Instant::now();
    let index = build_index_from_zip(osv_eco, &bytes)?;
    eprintln!(" done in {:.1}s", index_started.elapsed().as_secs_f64());
    save_index(osv_eco, &index)?;
    Ok(index)
}

/// Stream a URL into memory, printing download progress on stderr.
async fn download_with_progress(
    client: &reqwest::Client,
    url: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("download failed: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP {} for {url}", response.status()));
    }

    let total = response.content_length();
    let mut buf: Vec<u8> = match total.and_then(|n| usize::try_from(n).ok()) {
        Some(n) => Vec::with_capacity(n),
        None => Vec::with_capacity(1024 * 1024),
    };
    let mut downloaded: u64 = 0;
    let mut last_report = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let started = Instant::now();

    // Use Response::chunk so we can report progress without the "stream" feature.
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| anyhow!("read body: {e}"))?;
        let Some(chunk) = chunk else {
            break;
        };
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        buf.extend_from_slice(&chunk);

        // Throttle redraws (~5/s) so huge dumps don't flood I/O
        if last_report.elapsed() >= Duration::from_millis(200) {
            print_download_progress(label, downloaded, total, started.elapsed());
            last_report = Instant::now();
        }
    }
    print_download_progress(label, downloaded, total, started.elapsed());
    eprintln!(); // finish the \r line
    Ok(buf)
}

fn print_download_progress(label: &str, downloaded: u64, total: Option<u64>, elapsed: Duration) {
    let secs = elapsed.as_secs().max(1);
    let speed = downloaded / secs;
    let msg = match total {
        Some(t) if t > 0 => {
            let pct = downloaded.saturating_mul(100) / t;
            format!(
                "  downloading {label}: {} / {} ({pct:3}%)  {}/s",
                format_bytes(downloaded),
                format_bytes(t),
                format_bytes(speed),
            )
        }
        _ => format!(
            "  downloading {label}: {}  {}/s",
            format_bytes(downloaded),
            format_bytes(speed),
        ),
    };
    eprint!("\r{msg:<72}");
    let _ = std::io::stderr().flush();
}

fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{}.{:02} GB", n / GB, (n % GB) * 100 / GB)
    } else if n >= MB {
        format!("{}.{} MB", n / MB, (n % MB) * 10 / MB)
    } else if n >= KB {
        format!("{} KB", n / KB)
    } else {
        format!("{n} B")
    }
}

/// Build [`EcosystemIndex`] from an OSV ecosystem `all.zip` bytes.
pub fn build_index_from_zip(osv_eco: &str, zip_bytes: &[u8]) -> Result<EcosystemIndex> {
    let reader = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open OSV zip")?;

    let mut packages: HashMap<String, Vec<IndexedAdvisory>> = HashMap::new();
    let mut advisory_count = 0usize;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("zip entry")?;
        let name = file.name().to_string();
        if !name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        // skip directory entries
        if file.is_dir() {
            continue;
        }
        let mut text = String::new();
        if file.read_to_string(&mut text).is_err() {
            continue;
        }
        let Ok(vuln) = serde_json::from_str::<DumpVuln>(&text) else {
            continue;
        };
        // skip withdrawn
        if vuln.withdrawn.is_some() {
            continue;
        }
        let Some(id) = vuln.id.clone() else {
            continue;
        };

        let is_malware = id.starts_with("MAL-")
            || vuln
                .database_specific
                .as_ref()
                .and_then(|d| d.get("malicious"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        let severity = map_severity_from_raw(
            &OsvVulnLike {
                severity: vuln.severity.as_ref().map(|sevs| {
                    sevs.iter()
                        .map(|s| OsvSeverity {
                            type_: s.type_.clone(),
                            score: s.score.clone(),
                        })
                        .collect()
                }),
                database_specific: vuln.database_specific.clone(),
            },
            is_malware,
        );
        let summary = vuln
            .summary
            .clone()
            .or_else(|| vuln.details.clone())
            .unwrap_or_else(|| id.clone())
            .chars()
            .take(280)
            .collect::<String>();

        let mut any = false;
        for affected in vuln.affected.unwrap_or_default() {
            let Some(pkg) = affected.package else {
                continue;
            };
            if pkg.ecosystem.as_deref() != Some(osv_eco) {
                // some records multi-ecosystem; only index matching dump ecosystem
                continue;
            }
            let Some(pkg_name) = pkg.name else {
                continue;
            };
            let key = if osv_eco == "PyPI" {
                pkg_name.to_ascii_lowercase()
            } else {
                pkg_name
            };

            let mut versions = affected.versions.unwrap_or_default();
            // Cap huge exact-version lists to keep index size reasonable
            if versions.len() > 200 {
                versions.truncate(200);
            }

            let ranges = parse_ranges(affected.ranges.as_ref());
            if versions.is_empty() && ranges.is_empty() {
                continue;
            }

            let adv = IndexedAdvisory {
                id: id.clone(),
                summary: summary.clone(),
                severity: severity.clone(),
                is_malware,
                versions,
                ranges,
            };
            packages.entry(key).or_default().push(adv);
            any = true;
        }
        if any {
            advisory_count += 1;
        }
    }

    let package_count = packages.len();
    Ok(EcosystemIndex {
        packages,
        advisory_count,
        package_count,
    })
}

fn parse_ranges(ranges: Option<&Vec<DumpRange>>) -> Vec<IndexedRange> {
    let Some(ranges) = ranges else {
        return vec![];
    };
    let mut out = Vec::new();
    for r in ranges {
        // Prefer ECOSYSTEM and SEMVER; skip GIT for package version queries
        let rtype = r.type_.as_deref().unwrap_or("");
        if rtype == "GIT" {
            continue;
        }
        let events = r.events.as_deref().unwrap_or(&[]);
        let mut introduced = "0".to_string();
        let mut fixed = None;
        let mut last_affected = None;
        for ev in events {
            if let Some(v) = &ev.introduced {
                introduced.clone_from(v);
            }
            if let Some(v) = &ev.fixed {
                fixed = Some(v.clone());
            }
            if let Some(v) = &ev.last_affected {
                last_affected = Some(v.clone());
            }
        }
        out.push(IndexedRange {
            introduced,
            fixed,
            last_affected,
        });
    }
    out
}

fn unix_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

// ─── dump JSON shapes (subset of OSV schema) ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct DumpVuln {
    id: Option<String>,
    summary: Option<String>,
    details: Option<String>,
    withdrawn: Option<serde_json::Value>,
    affected: Option<Vec<DumpAffected>>,
    severity: Option<Vec<DumpSeverity>>,
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DumpAffected {
    package: Option<DumpPackage>,
    ranges: Option<Vec<DumpRange>>,
    versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct DumpPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DumpRange {
    #[serde(rename = "type")]
    type_: Option<String>,
    events: Option<Vec<DumpEvent>>,
}

#[derive(Debug, Deserialize)]
struct DumpEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DumpSeverity {
    #[serde(rename = "type")]
    type_: Option<String>,
    score: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ranges_skips_git() {
        let ranges = vec![
            DumpRange {
                type_: Some("GIT".into()),
                events: Some(vec![DumpEvent {
                    introduced: Some("abc".into()),
                    fixed: None,
                    last_affected: None,
                }]),
            },
            DumpRange {
                type_: Some("ECOSYSTEM".into()),
                events: Some(vec![
                    DumpEvent {
                        introduced: Some("1.0.0".into()),
                        fixed: None,
                        last_affected: None,
                    },
                    DumpEvent {
                        introduced: None,
                        fixed: Some("1.2.0".into()),
                        last_affected: None,
                    },
                ]),
            },
        ];
        let r = parse_ranges(Some(&ranges));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].introduced, "1.0.0");
        assert_eq!(r[0].fixed.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn test_build_index_from_minimal_zip() {
        // Build a tiny zip in memory with one vuln JSON
        use std::io::Write;
        let vuln = r#"{
          "id": "MAL-TEST-1",
          "summary": "evil",
          "affected": [{
            "package": {"name": "Evil-Pkg", "ecosystem": "PyPI"},
            "versions": ["1.0.0"],
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
          }]
        }"#;
        let withdrawn = r#"{
          "id": "WITHDRAWN-1",
          "withdrawn": "2020-01-01T00:00:00Z",
          "affected": [{
            "package": {"name": "x", "ecosystem": "PyPI"},
            "versions": ["1.0.0"]
          }]
        }"#;
        let other_eco = r#"{
          "id": "OTHER-1",
          "summary": "npm only",
          "affected": [{
            "package": {"name": "left-pad", "ecosystem": "npm"},
            "versions": ["1.0.0"]
          }]
        }"#;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zipw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zipw.start_file("MAL-TEST-1.json", opts).unwrap();
            zipw.write_all(vuln.as_bytes()).unwrap();
            zipw.start_file("WITHDRAWN-1.json", opts).unwrap();
            zipw.write_all(withdrawn.as_bytes()).unwrap();
            zipw.start_file("OTHER-1.json", opts).unwrap();
            zipw.write_all(other_eco.as_bytes()).unwrap();
            zipw.start_file("readme.txt", opts).unwrap();
            zipw.write_all(b"not json").unwrap();
            zipw.finish().unwrap();
        }
        let bytes = cursor.into_inner();
        let index = build_index_from_zip("PyPI", &bytes).unwrap();
        assert_eq!(index.package_count, 1);
        assert!(index.packages.contains_key("evil-pkg")); // lowercased
        assert_eq!(index.packages["evil-pkg"][0].id, "MAL-TEST-1");
        assert!(index.packages["evil-pkg"][0].is_malware);
        assert!(!index.packages.contains_key("left-pad"));
    }

    #[test]
    fn test_default_ecosystems_and_dump_url() {
        assert_eq!(default_ecosystems().len(), 4);
        assert!(dump_url("PyPI").contains("PyPI/all.zip"));
        assert!(dump_url("crates.io").contains("crates.io"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_update_osv_from_local_http_zip() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        // Tiny zip body for PyPI
        let vuln = r#"{
          "id": "MAL-HTTP-1",
          "summary": "from http",
          "affected": [{
            "package": {"name": "http-evil", "ecosystem": "PyPI"},
            "versions": ["0.0.1"],
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
          }]
        }"#;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zipw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zipw.start_file("MAL-HTTP-1.json", opts).unwrap();
            zipw.write_all(vuln.as_bytes()).unwrap();
            zipw.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let zip_clone = zip_bytes.clone();
        thread::spawn(move || {
            // serve a few requests (success + maybe HEAD)
            for _ in 0..4 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/zip\r\nConnection: close\r\n\r\n",
                        zip_clone.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(&zip_clone);
                }
            }
        });

        let dir = std::env::temp_dir().join(format!("osv-upd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PKG_GUARD_CACHE_DIR", &dir);
        std::env::set_var(
            "PKG_GUARD_OSV_DUMP_BASE",
            format!("http://127.0.0.1:{port}"),
        );
        super::super::local::clear_memory_cache();

        let result = update_osv(&[Ecosystem::Python]).await;
        assert!(result.is_ok(), "{result:?}");
        let result = result.unwrap();
        assert!(result.ecosystems.iter().any(|e| e.ok));
        assert!(result.ecosystems[0].advisory_count >= 1);

        // all fail path
        std::env::set_var("PKG_GUARD_OSV_DUMP_BASE", "http://127.0.0.1:1");
        let fail = update_osv(&[Ecosystem::Cargo]).await;
        assert!(fail.is_err());

        std::env::remove_var("PKG_GUARD_OSV_DUMP_BASE");
        std::env::remove_var("PKG_GUARD_CACHE_DIR");
        super::super::local::clear_memory_cache();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
