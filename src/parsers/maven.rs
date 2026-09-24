//! Java dependency sources for `scan`: `pom.xml`, `gradle.lockfile`, and
//! `mvn dependency:list` output.
//!
//! `pom.xml` only declares **direct** dependencies, and versions often come
//! from `${properties}`, `<dependencyManagement>`, a parent POM, or a BOM.
//! Properties and local dependency management are resolved; anything else is
//! reported as unresolved rather than guessed. For the full transitive tree,
//! scan `mvn dependency:list` output (or a `gradle.lockfile`).

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::data::blocklist::is_blocklisted;
use crate::data::{Ecosystem, MaliciousFinding};

/// Marker line written by `mvn dependency:list`.
const DEPENDENCY_LIST_MARKER: &str = "The following files have been resolved:";

/// Dependencies found in a Java build file.
#[derive(Debug, Default)]
pub(crate) struct JavaDeps {
    /// `groupId:artifactId` with a concrete version.
    pub resolved: Vec<(String, String)>,
    /// `groupId:artifactId (reason)` for versions that could not be resolved.
    pub unresolved: Vec<String>,
}

impl JavaDeps {
    /// Every dependency name (resolved or not) for blocklist checks.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.resolved.iter().map(|(n, _)| n.as_str()).chain(
            self.unresolved
                .iter()
                .map(|u| u.split(' ').next().unwrap_or(u)),
        )
    }
}

/// Java dependencies for a scannable file, or `None` if it is not one.
pub(crate) fn java_deps(filename: &str, content: &str) -> Option<JavaDeps> {
    if filename == "pom.xml" {
        Some(parse_pom(content))
    } else if filename == "gradle.lockfile" {
        Some(parse_gradle_lockfile(content))
    } else if is_dependency_list(content) {
        Some(parse_dependency_list(content))
    } else {
        None
    }
}

/// Blocklist hits by `groupId:artifactId`.
pub(crate) fn blocklist_findings(deps: &JavaDeps) -> Vec<MaliciousFinding> {
    let versions: HashMap<&str, &str> = deps
        .resolved
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    deps.names()
        .filter(|n| is_blocklisted(Ecosystem::Java, n))
        .map(|n| MaliciousFinding {
            package: n.to_string(),
            version: versions.get(n).map(ToString::to_string),
            severity: "CRITICAL".to_string(),
            reason: "Package is on the known-malicious blocklist".to_string(),
        })
        .collect()
}

/// Status suffix: unresolved versions, and the direct-only caveat for POMs.
pub(crate) fn coverage_note(file_path: &str, unresolved: usize) -> String {
    let mut note = String::new();
    if unresolved > 0 {
        let _ = write!(
            note,
            "; {unresolved} dependency version(s) unresolved, name-checked only (see unresolved_dependencies)"
        );
    }
    if std::path::Path::new(file_path).file_name() == Some("pom.xml".as_ref()) {
        note.push_str(
            "; pom.xml lists direct dependencies only; for the full tree scan the output of \
             `mvn dependency:list -DoutputFile=deps.txt`",
        );
    }
    note
}

/// True for `mvn dependency:list` output (matched on content, any file name).
pub(crate) fn is_dependency_list(content: &str) -> bool {
    content.contains(DEPENDENCY_LIST_MARKER)
}

/// Parse `mvn dependency:list` output (file or captured stdout with `[INFO]`).
///
/// Lines look like `group:artifact:type[:classifier]:version:scope`, optionally
/// followed by ` -- module …`.
pub(crate) fn parse_dependency_list(content: &str) -> JavaDeps {
    let mut deps = JavaDeps::default();
    let mut in_list = false;
    for line in content.lines() {
        let line = line.trim().trim_start_matches("[INFO]").trim();
        if line.contains(DEPENDENCY_LIST_MARKER) {
            in_list = true;
            continue;
        }
        if !in_list || line.is_empty() {
            continue;
        }
        let coords = line.split_whitespace().next().unwrap_or("");
        let parts: Vec<&str> = coords.split(':').collect();
        let version = match parts.len() {
            5 => parts[3],
            6 => parts[4],
            _ => continue,
        };
        push_dep(&mut deps, parts[0], parts[1], version);
    }
    deps
}

/// Parse a Gradle `gradle.lockfile` (`group:artifact:version=configurations`).
pub(crate) fn parse_gradle_lockfile(content: &str) -> JavaDeps {
    let mut deps = JavaDeps::default();
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        let coords = line.split('=').next().unwrap_or("");
        let parts: Vec<&str> = coords.split(':').collect();
        if let [group, artifact, version] = parts[..] {
            push_dep(&mut deps, group, artifact, version);
        }
    }
    deps
}

fn push_dep(deps: &mut JavaDeps, group: &str, artifact: &str, version: &str) {
    if group.is_empty() || artifact.is_empty() {
        return;
    }
    let name = format!("{group}:{artifact}");
    if version.is_empty() {
        deps.unresolved.push(format!("{name} (no version)"));
    } else {
        deps.resolved.push((name, version.to_string()));
    }
}

/// One `<dependency>` element.
#[derive(Debug, Default, Clone)]
struct PomDep {
    group: String,
    artifact: String,
    version: String,
    scope: String,
    managed: bool,
}

/// Parse a `pom.xml`: direct dependencies (including profile and plugin
/// dependencies) plus BOM imports, with `${…}` and local
/// `<dependencyManagement>` versions resolved.
pub(crate) fn parse_pom(content: &str) -> JavaDeps {
    let mut props: HashMap<String, String> = HashMap::new();
    let mut deps: Vec<PomDep> = Vec::new();
    let mut current: Option<PomDep> = None;
    let mut stack: Vec<String> = Vec::new();

    for token in xml_tokens(content) {
        match token {
            XmlToken::Open(name) => {
                if name == "dependency" {
                    current = Some(PomDep {
                        managed: stack.iter().any(|s| s == "dependencyManagement"),
                        ..PomDep::default()
                    });
                }
                stack.push(name);
            }
            XmlToken::Close(name) => {
                if name == "dependency" {
                    deps.extend(current.take());
                }
                if let Some(pos) = stack.iter().rposition(|s| *s == name) {
                    stack.truncate(pos);
                }
            }
            XmlToken::Text(text) => {
                let path: Vec<&str> = stack.iter().map(String::as_str).collect();
                record_text(&path, text, &mut props, current.as_mut());
            }
        }
    }

    let managed: HashMap<String, String> = deps
        .iter()
        .filter(|d| d.managed && !d.version.is_empty())
        .map(|d| (format!("{}:{}", d.group, d.artifact), d.version.clone()))
        .collect();

    let mut out = JavaDeps::default();
    for d in &deps {
        // Managed entries only pin versions, except BOM imports, which are fetched.
        if d.managed && d.scope != "import" {
            continue;
        }
        let group = resolve_props(&d.group, &props);
        let artifact = resolve_props(&d.artifact, &props);
        let name = format!("{group}:{artifact}");
        let raw = if d.version.is_empty() {
            managed.get(&format!("{}:{}", d.group, d.artifact)).cloned()
        } else {
            Some(d.version.clone())
        };
        match raw.map(|v| resolve_props(&v, &props)) {
            None => out
                .unresolved
                .push(format!("{name} (version from parent POM or BOM)")),
            Some(v) if v.contains("${") => out
                .unresolved
                .push(format!("{name} (undefined property in {v})")),
            Some(v) if is_dynamic(&v) => {
                out.unresolved.push(format!("{name} (dynamic version {v})"));
            }
            Some(v) => out.resolved.push((name, v)),
        }
    }
    out
}

fn record_text(
    path: &[&str],
    text: &str,
    props: &mut HashMap<String, String>,
    dep: Option<&mut PomDep>,
) {
    let text = text.trim();
    match path {
        ["project", "properties", key] => {
            props.insert((*key).to_string(), text.to_string());
        }
        ["project", "version"] => {
            for k in ["project.version", "version", "pom.version"] {
                props.insert(k.into(), text.to_string());
            }
        }
        ["project", "groupId"] => {
            props.insert("project.groupId".into(), text.to_string());
        }
        ["project", "parent", "version"] => {
            props.insert("project.parent.version".into(), text.to_string());
            props
                .entry("project.version".into())
                .or_insert_with(|| text.to_string());
        }
        ["project", "parent", "groupId"] => {
            props
                .entry("project.groupId".into())
                .or_insert_with(|| text.to_string());
        }
        [.., "dependency", field] => {
            if let Some(d) = dep {
                let slot = match *field {
                    "groupId" => &mut d.group,
                    "artifactId" => &mut d.artifact,
                    "version" => &mut d.version,
                    "scope" => &mut d.scope,
                    _ => return,
                };
                *slot = text.to_string();
            }
        }
        _ => {}
    }
}

/// Maven ranges and moving targets are not concrete versions.
fn is_dynamic(v: &str) -> bool {
    v.starts_with('[')
        || v.starts_with('(')
        || v.contains(',')
        || v == "LATEST"
        || v == "RELEASE"
        || v.ends_with("-SNAPSHOT")
}

/// Substitute `${name}` from `props` (nested references allowed).
fn resolve_props(value: &str, props: &HashMap<String, String>) -> String {
    const MAX_PASSES: usize = 10;
    let mut out = value.to_string();
    for _ in 0..MAX_PASSES {
        let Some(start) = out.find("${") else { break };
        let Some(len) = out[start..].find('}') else {
            break;
        };
        let key = &out[start + 2..start + len];
        let Some(val) = props.get(key) else { break };
        out = format!("{}{val}{}", &out[..start], &out[start + len + 1..]);
    }
    out
}

#[derive(Debug, PartialEq)]
enum XmlToken<'a> {
    Open(String),
    Close(String),
    Text(&'a str),
}

/// Minimal XML tokenizer: element open/close and text. Comments, CDATA-free
/// declarations, processing instructions, and self-closing tags are skipped.
fn xml_tokens(content: &str) -> Vec<XmlToken<'_>> {
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(lt) = rest.find('<') {
        let text = &rest[..lt];
        if !text.trim().is_empty() {
            out.push(XmlToken::Text(text));
        }
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |e| &after[e + 3..]);
            continue;
        }
        let Some(gt) = rest.find('>') else { break };
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        if tag.starts_with('?') || tag.starts_with('!') || tag.ends_with('/') {
            continue;
        }
        let name = |t: &str| t.split_whitespace().next().unwrap_or("").to_string();
        match tag.strip_prefix('/') {
            Some(closing) => out.push(XmlToken::Close(name(closing))),
            None => out.push(XmlToken::Open(name(tag))),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const POM: &str = r#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.4.0</version>
  </parent>
  <artifactId>app</artifactId>
  <properties>
    <jackson.version>2.9.8</jackson.version>
    <log4j.base>2.14</log4j.base>
    <log4j.version>${log4j.base}.1</log4j.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.7.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.0-jre</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <!-- <dependency><groupId>commented</groupId><artifactId>out</artifactId></dependency> -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
    <dependency>
      <groupId>x</groupId><artifactId>undef</artifactId><version>${nope}</version>
    </dependency>
    <dependency>
      <groupId>x</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
  <build><plugins><plugin>
    <artifactId>maven-shade-plugin</artifactId>
    <dependencies><dependency>
      <groupId>org.ow2.asm</groupId><artifactId>asm</artifactId><version>9.5</version>
    </dependency></dependencies>
  </plugin></plugins></build>
</project>"#;

    #[test]
    fn pom_resolves_properties_management_and_reports_gaps() {
        let d = parse_pom(POM);
        let resolved: HashMap<&str, &str> = d
            .resolved
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            resolved["com.fasterxml.jackson.core:jackson-databind"],
            "2.9.8"
        );
        assert_eq!(resolved["org.apache.logging.log4j:log4j-core"], "2.14.1");
        assert_eq!(resolved["com.google.guava:guava"], "31.0-jre");
        assert_eq!(resolved["org.example:sibling"], "1.4.0");
        assert_eq!(
            resolved["org.springframework.boot:spring-boot-dependencies"],
            "2.7.0"
        );
        assert_eq!(resolved["org.ow2.asm:asm"], "9.5");
        assert!(!resolved.contains_key("commented:out"));
        assert_eq!(d.resolved.len(), 6);

        assert_eq!(d.unresolved.len(), 3, "{:?}", d.unresolved);
        assert!(d.unresolved[0].starts_with("org.slf4j:slf4j-api (version from parent POM or BOM)"));
        assert!(d.unresolved[1].contains("undefined property in ${nope}"));
        assert!(d.unresolved[2].contains("dynamic version [1.0,2.0)"));
        assert_eq!(d.names().count(), 9);
        assert!(d.names().any(|n| n == "org.slf4j:slf4j-api"));
    }

    #[test]
    fn dependency_list_file_and_stdout() {
        let file = "\nThe following files have been resolved:\n   org.slf4j:slf4j-api:jar:2.0.9:compile\n   com.google.guava:guava:jar:32.1.2-jre:compile -- module com.google.common\n   io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100.Final:runtime\n\n";
        assert!(is_dependency_list(file));
        let d = parse_dependency_list(file);
        assert_eq!(
            d.resolved,
            [
                ("org.slf4j:slf4j-api".to_string(), "2.0.9".to_string()),
                ("com.google.guava:guava".into(), "32.1.2-jre".into()),
                (
                    "io.netty:netty-transport-native-epoll".into(),
                    "4.1.100.Final".into()
                ),
            ]
        );
        let stdout = "[INFO] --- dependency:3.6.0:list ---\n[INFO] \n[INFO] The following files have been resolved:\n[INFO]    junit:junit:jar:4.12:test\n[INFO] \n[INFO] BUILD SUCCESS\n";
        let d = parse_dependency_list(stdout);
        assert_eq!(
            d.resolved,
            [("junit:junit".to_string(), "4.12".to_string())]
        );
        assert!(!is_dependency_list("requests==2.0\n"));
    }

    #[test]
    fn gradle_lockfile() {
        let lock = "# This is a Gradle generated file\ncom.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\norg.slf4j:slf4j-api:2.0.9=runtimeClasspath\nbad-line\nempty=annotationProcessor\n";
        let d = parse_gradle_lockfile(lock);
        assert_eq!(d.resolved.len(), 2);
        assert_eq!(
            d.resolved[0],
            ("com.google.guava:guava".into(), "32.1.2-jre".into())
        );
        let mut d = JavaDeps::default();
        push_dep(&mut d, "g", "a", "");
        push_dep(&mut d, "", "a", "1");
        assert_eq!(d.unresolved, ["g:a (no version)"]);
    }

    #[test]
    fn xml_tokens_skip_noise() {
        let t = xml_tokens("<?xml?><!DOCTYPE x><a k=\"v\"><b/>t<!-- c --></a>");
        assert_eq!(
            t,
            [
                XmlToken::Open("a".into()),
                XmlToken::Text("t"),
                XmlToken::Close("a".into())
            ]
        );
        assert_eq!(
            resolve_props(
                "${a}-${missing}",
                &HashMap::from([("a".into(), "1".into())])
            ),
            "1-${missing}"
        );
    }
}
