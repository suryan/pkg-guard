//! Embedded blocklist of known malicious packages
//! Compiled into the binary — no external file needed at runtime.

use std::collections::HashSet;
use std::sync::LazyLock;

use super::Ecosystem;

/// Known malicious Python packages
static PYTHON_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "reqeusts",
        "requsets",
        "request",
        "python-requests",
        "python3-dateutil",
        "jeIlyfish",
        "jellyfish-py",
        "python-sqlite",
        "colourfool",
        "beautifulsoup",
        "beutifulsoup4",
        "bs4",
        "nmap-python",
        "python-nmap-scan",
        "openvc-python",
        "open-cv-python",
        "opencv",
        "tensorfow",
        "tenserflow",
        "tensorflw",
        "pytorch-utils",
        "torchvision-utils",
        "scikit-learn-utils",
        "pylint-utils",
        "flassk",
        "flaask",
        "djang0",
        "dajngo",
        "numpyy",
        "panadas",
        "pandass",
        "matplotlibb",
        "pilliow",
        "pyyaml-lib",
        "cryptograpy",
        "cryptographyy",
        "urlib3",
        "urllib33",
        "coloramma",
        "colrama",
        "boto33",
        "botocore2",
        "setuptoolss",
        "pipinstall",
        "pip-install",
        "pipsecurity",
        "importlib-metdata",
        "pydanticc",
        "fastaapi",
        "uvicornx",
        "sqlalchemyy",
        "celeryx",
        "reddis",
        "psycopg22",
        "seleniium",
        "pytestt",
        "clickk",
        "ctx",
        "atomicwrites2",
        "colourama",
    ]
    .into_iter()
    .collect()
});

/// Known malicious npm packages
static NPM_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "expres",
        "expresss",
        "exprss",
        "reactt",
        "react-domm",
        "lodasch",
        "lodahs",
        "1odash",
        "lodash-js",
        "lodash-utils",
        "axois",
        "axioss",
        "chalks",
        "chaIk",
        "chalkk",
        "comander",
        "commanderr",
        "debugg",
        "dotenvv",
        "dot-env",
        "eslintt",
        "jestt",
        "jset",
        "mochaa",
        "momentjs",
        "moment-js",
        "mongooose",
        "mongose",
        "mysqll",
        "nextjs",
        "next-js",
        "nodemoon",
        "nodmon",
        "passsport",
        "pgg",
        "pretier",
        "prettieer",
        "typescriptt",
        "typescrpt",
        "uuidd",
        "webpackk",
        "web-pack",
        "yargss",
        "flatmap-stream",
        "crossenv",
        "cross-env.js",
        "crossenv2",
        "babelcli",
        "babel-cIi",
        "jquerry",
        "socket-io",
        "bcryptt",
        "jsonwebtokenn",
        "json-web-token",
        "multerr",
        "sharpp",
        "pupeteer",
        "puppetter",
        "cheerioo",
        "dayjss",
        "inquirerr",
        "globb",
        "rimraaff",
        "semverr",
        "minimistt",
        "node-fetchh",
        "form-dataa",
        "mimee",
        "asyncc",
        "underscoree",
    ]
    .into_iter()
    .collect()
});

/// Known malicious/vulnerable Java packages (groupId:artifactId or just name)
static JAVA_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "io.github.nichetoolkit:mybatis-toolkit",
        "io.github.nichetoolkit:jts-toolkit",
        "bytecode-viewer",
        "org.webjars.npm:malicious-package-example",
    ]
    .into_iter()
    .collect()
});

/// Popular packages per ecosystem (for typosquat detection)
pub static POPULAR_PYTHON: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "requests",
        "flask",
        "django",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "beautifulsoup4",
        "selenium",
        "pillow",
        "pytest",
        "setuptools",
        "pip",
        "wheel",
        "boto3",
        "botocore",
        "urllib3",
        "certifi",
        "charset-normalizer",
        "idna",
        "typing-extensions",
        "pyyaml",
        "cryptography",
        "jinja2",
        "markupsafe",
        "click",
        "pygments",
        "colorama",
        "python-dateutil",
        "pytz",
        "six",
        "packaging",
        "attrs",
        "pluggy",
        "more-itertools",
        "zipp",
        "importlib-metadata",
        "tomli",
        "pydantic",
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "alembic",
        "celery",
        "redis",
        "psycopg2",
        "opencv-python",
        "tensorflow",
        "torch",
        "transformers",
        "scikit-learn",
    ]
});

pub static POPULAR_NPM: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "express",
        "react",
        "react-dom",
        "lodash",
        "axios",
        "chalk",
        "commander",
        "debug",
        "dotenv",
        "eslint",
        "jest",
        "mocha",
        "moment",
        "mongoose",
        "mysql",
        "next",
        "nodemon",
        "passport",
        "pg",
        "prettier",
        "socket.io",
        "typescript",
        "uuid",
        "webpack",
        "yargs",
        "body-parser",
        "cors",
        "cookie-parser",
        "jsonwebtoken",
        "bcrypt",
        "multer",
        "sharp",
        "puppeteer",
        "cheerio",
        "dayjs",
        "inquirer",
        "ora",
        "glob",
        "rimraf",
        "mkdirp",
        "semver",
        "minimist",
        "yallist",
        "lru-cache",
        "nan",
        "node-fetch",
        "form-data",
        "mime",
        "qs",
        "async",
        "underscore",
    ]
});

pub static POPULAR_JAVA: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "org.springframework:spring-core",
        "org.springframework.boot:spring-boot",
        "com.google.guava:guava",
        "org.apache.commons:commons-lang3",
        "org.slf4j:slf4j-api",
        "ch.qos.logback:logback-classic",
        "com.fasterxml.jackson.core:jackson-databind",
        "junit:junit",
        "org.mockito:mockito-core",
        "org.apache.httpcomponents:httpclient",
        "com.google.code.gson:gson",
        "org.projectlombok:lombok",
        "org.apache.logging.log4j:log4j-core",
        "io.netty:netty-all",
        "com.squareup.okhttp3:okhttp",
        "org.hibernate:hibernate-core",
    ]
});

/// Where a blocklist hit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistSource {
    /// Not on any blocklist
    None,
    /// User / project / env custom list (fast path for brand-new threats)
    Custom,
    /// Compiled-in seed list
    Builtin,
}

/// Check if a package is on the blocklist (custom lists first, then built-in seed).
#[must_use]
pub fn is_blocklisted(ecosystem: Ecosystem, package_name: &str) -> bool {
    !matches!(
        blocklist_source(ecosystem, package_name),
        BlocklistSource::None
    )
}

/// Report which list matched, if any.
///
/// Custom user/project lists are checked **before** the embedded seed so that
/// brand-new threats can be blocked without waiting for feeds or a release.
#[must_use]
pub fn blocklist_source(ecosystem: Ecosystem, package_name: &str) -> BlocklistSource {
    if super::custom_blocklist::is_custom_blocklisted(ecosystem, package_name) {
        return BlocklistSource::Custom;
    }
    let name_lower = package_name.to_lowercase();
    let builtin = match ecosystem {
        Ecosystem::Python => PYTHON_BLOCKLIST.contains(name_lower.as_str()),
        Ecosystem::Npm => NPM_BLOCKLIST.contains(name_lower.as_str()),
        Ecosystem::Java => JAVA_BLOCKLIST.contains(name_lower.as_str()),
    };
    if builtin {
        BlocklistSource::Builtin
    } else {
        BlocklistSource::None
    }
}

/// Get the popular packages list for an ecosystem
pub fn popular_packages(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Python => &POPULAR_PYTHON,
        Ecosystem::Npm => &POPULAR_NPM,
        Ecosystem::Java => &POPULAR_JAVA,
    }
}
