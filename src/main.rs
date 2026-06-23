use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use tempfile::TempDir;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const APKTOOL_VERSION: &str = "2.9.3";
const UBER_APK_SIGNER_VERSION: &str = "1.3.0";

static JAVA_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:1\.)?(\d+).*?""#).expect("valid Java version regex"));
static APPLICATION_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<application\b(?P<attrs>.*?)(?P<self>/?)>"#)
        .expect("valid application tag regex")
});
static META_DATA_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<meta-data\b(?P<attrs>.*?)(?P<self>/?)>"#).expect("valid meta-data tag regex")
});
static META_DATA_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\sandroid:value\s*=\s*(?:\"[^\"]*\"|'[^']*')"#)
        .expect("valid meta-data value regex")
});
static SMALI_CLASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.class(?P<keywords>.+)? L(?P<name>[^\s]+);").expect("valid smali class regex")
});
static SMALI_IMPLEMENTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.implements L(?P<name>[^\s]+);").expect("valid smali implements regex")
});

#[derive(Parser, Debug)]
#[command(
    name = "apk-mitm",
    version,
    about = "Prepare Android APK files for HTTPS inspection"
)]
struct Args {
    /// Path to APK, XAPK, APKS/ZIP, or decoded apktool directory
    input: PathBuf,

    /// Wait for manual changes before re-encoding
    #[arg(long)]
    wait: bool,

    /// Where temporary files will be stored
    #[arg(long = "tmp-dir")]
    tmp_dir: Option<PathBuf>,

    /// Don't delete the temporary directory after patching
    #[arg(long = "keep-tmp-dir")]
    keep_tmp_dir: bool,

    /// Make the patched app debuggable
    #[arg(long)]
    debuggable: bool,

    /// Don't apply any patches (for troubleshooting)
    #[arg(long = "skip-patches")]
    skip_patches: bool,

    /// Use custom version of Apktool
    #[arg(long)]
    apktool: Option<PathBuf>,

    /// Add specific certificate to network security config (.pem or .der)
    #[arg(long)]
    certificate: Option<PathBuf>,

    /// Add custom Google Maps API key to replace while patching APK
    #[arg(long = "maps-api-key")]
    maps_api_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskKind {
    Apk,
    Xapk,
    Apks,
}

#[derive(Debug)]
struct TaskInfo {
    kind: TaskKind,
    skip_decode: bool,
    is_app_bundle: bool,
    output_path: PathBuf,
    output_name: String,
}

#[derive(Debug)]
struct Options {
    input_path: PathBuf,
    output_path: PathBuf,
    tmp_dir: PathBuf,
    skip_patches: bool,
    certificate_path: Option<PathBuf>,
    maps_api_key: Option<String>,
    apktool: Apktool,
    signer: UberApkSigner,
    wait: bool,
    is_app_bundle: bool,
    debuggable: bool,
    skip_decode: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("\n  Failed! An error occurred:\n\n  {error:#}\n");
        if std::env::consts::ARCH.starts_with("arm") {
            eprintln!(
                "  NOTE\n\n  apk-mitm doesn't officially support ARM-based devices (like Raspberry Pi's).\n  Try patching this APK on x64 before reporting an issue.\n"
            );
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let input_path = fs::canonicalize(&args.input)
        .with_context(|| format!("Could not access input path {}", args.input.display()))?;
    let info = determine_task(&input_path)?;

    let certificate_path = match args.certificate {
        Some(path) => {
            let path = fs::canonicalize(&path)
                .with_context(|| format!("Could not access certificate {}", path.display()))?;
            match path.extension().and_then(OsStr::to_str) {
                Some("pem" | "der") => Some(path),
                _ => bail!("Only .pem and .der certificate files are supported."),
            }
        }
        None => None,
    };

    let mut owned_temp: Option<TempDir> = None;
    let tmp_dir = if let Some(tmp_dir) = args.tmp_dir {
        let path = absolute_path(tmp_dir)?;
        fs::create_dir_all(&path)?;
        path
    } else {
        let temp = tempfile::Builder::new().prefix("apk-mitm-").tempdir()?;
        let path = temp.path().to_path_buf();
        owned_temp = Some(temp);
        path
    };

    let apktool = Apktool::new(
        tmp_dir.join("framework"),
        args.apktool.map(absolute_path).transpose()?,
    );
    let signer = UberApkSigner::new();

    println!("\n  ╭ apk-mitm v{VERSION}");
    println!("  ├ apktool {}", apktool.version_name());
    println!("  ╰ uber-apk-signer {}\n", signer.version_name());
    if info.skip_decode {
        println!(
            "  Patching from decoded apktool directory:\n  {}\n",
            input_path.display()
        );
    } else {
        println!("  Using temporary directory:\n  {}\n", tmp_dir.display());
    }

    let options = Options {
        input_path,
        output_path: info.output_path.clone(),
        tmp_dir: tmp_dir.clone(),
        skip_patches: args.skip_patches,
        certificate_path,
        maps_api_key: args.maps_api_key,
        apktool,
        signer,
        wait: args.wait,
        is_app_bundle: info.is_app_bundle,
        debuggable: args.debuggable,
        skip_decode: info.skip_decode,
    };

    let uses_app_bundle = match info.kind {
        TaskKind::Apk => patch_apk(&options)?,
        TaskKind::Xapk => patch_app_bundle(&options, true)?,
        TaskKind::Apks => patch_app_bundle(&options, false)?,
    };

    if info.kind == TaskKind::Apk && uses_app_bundle {
        show_app_bundle_warning();
    }

    println!("\n  Done! Patched file: ./{}\n", info.output_name);

    if args.keep_tmp_dir {
        std::mem::forget(owned_temp);
    }

    Ok(())
}

fn absolute_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn determine_task(input_path: &Path) -> Result<TaskInfo> {
    let metadata = fs::metadata(input_path)?;
    let mut skip_decode = false;
    let mut is_app_bundle = false;
    let kind;
    let output_ext;

    if metadata.is_dir() {
        kind = TaskKind::Apk;
        skip_decode = true;
        output_ext = "apk";
        if !input_path.join("apktool.yml").exists() {
            bail!("No \"apktool.yml\" file found inside the input directory! Make sure to specify a directory created by \"apktool decode\".");
        }
    } else {
        let ext = input_path.extension().and_then(OsStr::to_str).unwrap_or("");
        output_ext = ext;
        match ext {
            "apk" => kind = TaskKind::Apk,
            "xapk" => {
                kind = TaskKind::Xapk;
                is_app_bundle = true;
            }
            "apks" | "zip" => {
                kind = TaskKind::Apks;
                is_app_bundle = true;
            }
            _ => bail!("Unsupported file type. Supported extensions: .apk, .xapk, .apks, .zip, or a decoded apktool directory."),
        }
    }

    let base_name = input_path
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("Could not determine input file name"))?;
    let output_name = format!("{base_name}-patched.{output_ext}");
    let output_path = input_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&output_name);

    Ok(TaskInfo {
        kind,
        skip_decode,
        is_app_bundle,
        output_path,
        output_name,
    })
}

fn patch_apk(options: &Options) -> Result<bool> {
    step("Checking prerequisites", || check_prerequisites(options))?;

    let decode_dir = if options.skip_decode {
        options.input_path.clone()
    } else {
        options.tmp_dir.join("decode")
    };
    let tmp_apk_path = options.tmp_dir.join("tmp.apk");

    if !options.skip_decode {
        step("Decoding APK file", || {
            options
                .apktool
                .decode(&options.input_path, &decode_dir, &options.tmp_dir)
        })?;
    }

    let mut uses_app_bundle = false;
    if !options.skip_patches {
        uses_app_bundle = step("Applying patches", || apply_patches(&decode_dir, options))?;
    }

    if options.wait {
        step("Waiting for you to make changes", || {
            println!("  Press Enter to continue.");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Ok(())
        })?;
    }

    println!("  Encoding patched APK file");
    match options
        .apktool
        .encode(&decode_dir, &tmp_apk_path, true, &options.tmp_dir)
    {
        Ok(_) => println!("    ✓ Encoding using AAPT2"),
        Err(error) => {
            println!("    ! AAPT2 failed, falling back to AAPT: {error}");
            options
                .apktool
                .encode(&decode_dir, &tmp_apk_path, false, &options.tmp_dir)?;
            println!("    ✓ Encoding using AAPT fallback");
        }
    }

    step("Signing patched APK file", || {
        options
            .signer
            .sign(std::slice::from_ref(&tmp_apk_path), true, &options.tmp_dir)?;
        fs::copy(&tmp_apk_path, &options.output_path)?;
        Ok(())
    })?;

    Ok(uses_app_bundle)
}

fn patch_app_bundle(options: &Options, is_xapk: bool) -> Result<bool> {
    step("Checking prerequisites", || check_prerequisites(options))?;

    let bundle_dir = options.tmp_dir.join("bundle");
    step("Extracting APKs", || {
        unzip_file(&options.input_path, &bundle_dir)
    })?;

    let mut base_apk_path = bundle_dir.join("base.apk");
    if is_xapk {
        step("Finding base APK path", || {
            base_apk_path = find_xapk_base_apk(&bundle_dir)?;
            Ok(())
        })?;
    }

    let base_options = Options {
        input_path: base_apk_path.clone(),
        output_path: base_apk_path.clone(),
        tmp_dir: options.tmp_dir.join("base-apk"),
        skip_patches: options.skip_patches,
        certificate_path: options.certificate_path.clone(),
        maps_api_key: options.maps_api_key.clone(),
        apktool: Apktool::new(
            options.tmp_dir.join("base-apk/framework"),
            options.apktool.custom_path.clone(),
        ),
        signer: UberApkSigner::new(),
        wait: options.wait,
        is_app_bundle: true,
        debuggable: options.debuggable,
        skip_decode: false,
    };

    step("Patching base APK", || patch_apk(&base_options).map(|_| ()))?;

    step("Signing APKs", || {
        let apks: Vec<PathBuf> = WalkDir::new(&bundle_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("apk"))
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();
        options.signer.sign(&apks, false, &options.tmp_dir)
    })?;

    step("Compressing APKs", || {
        zip_dir(&bundle_dir, &options.output_path)
    })?;
    Ok(false)
}

fn step<T>(name: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    print!("  {name} ... ");
    io::stdout().flush().ok();
    match f() {
        Ok(value) => {
            println!("✓");
            Ok(value)
        }
        Err(error) => {
            println!("✗");
            Err(error)
        }
    }
}

fn check_prerequisites(options: &Options) -> Result<()> {
    let java_major = get_java_major_version()?;
    if java_major < 8 {
        bail!("apk-mitm requires at least Java 8; found Java {java_major}.");
    }
    if options.is_app_bundle && !cfg!(windows) {
        ensure_command("zip")?;
        ensure_command("unzip")?;
    }
    options.apktool.ensure_downloaded()?;
    options.signer.ensure_downloaded()?;
    Ok(())
}

fn ensure_command(name: &str) -> Result<()> {
    let status = Command::new(name)
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => bail!("apk-mitm requires the command \"{name}\" when patching App Bundles."),
    }
}

fn get_java_major_version() -> Result<u32> {
    let output = Command::new("java").arg("-version").output().context(
        "No \"java\" executable could be found. Make sure Java is installed and available in PATH.",
    )?;
    let text = String::from_utf8_lossy(&output.stderr);
    let major = JAVA_VERSION_RE
        .captures(&text)
        .and_then(|caps| caps.get(1))
        .ok_or_else(|| {
            anyhow!("Could not extract Java major version from java -version output:\n{text}")
        })?
        .as_str()
        .parse()?;
    Ok(major)
}

#[derive(Debug, Clone)]
struct Apktool {
    framework_path: PathBuf,
    custom_path: Option<PathBuf>,
}

impl Apktool {
    fn new(framework_path: PathBuf, custom_path: Option<PathBuf>) -> Self {
        Self {
            framework_path,
            custom_path,
        }
    }

    fn version_name(&self) -> String {
        if self.custom_path.is_some() {
            "custom version".into()
        } else {
            format!("v{APKTOOL_VERSION}")
        }
    }

    fn jar_path(&self) -> PathBuf {
        self.custom_path
            .clone()
            .unwrap_or_else(|| cache_path(&format!("apktool-v{APKTOOL_VERSION}.jar")))
    }

    fn ensure_downloaded(&self) -> Result<()> {
        if self.custom_path.is_some() {
            return Ok(());
        }
        download_cached(
            &self.jar_path(),
            &format!("https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"),
        )
    }

    fn decode(&self, input: &Path, output: &Path, tmp_dir: &Path) -> Result<()> {
        self.run(
            &[
                "decode".into(),
                input.display().to_string(),
                "--output".into(),
                output.display().to_string(),
                "--frame-path".into(),
                self.framework_path.display().to_string(),
            ],
            "decoding",
            tmp_dir,
        )
    }

    fn encode(&self, input: &Path, output: &Path, use_aapt2: bool, tmp_dir: &Path) -> Result<()> {
        let mut args = vec![
            "build".into(),
            input.display().to_string(),
            "--output".into(),
            output.display().to_string(),
            "--frame-path".into(),
            self.framework_path.display().to_string(),
        ];
        if use_aapt2 {
            args.push("--use-aapt2".into());
        }
        self.run(
            &args,
            if use_aapt2 {
                "encoding-aapt2"
            } else {
                "encoding-aapt"
            },
            tmp_dir,
        )
    }

    fn run(&self, args: &[String], log_name: &str, tmp_dir: &Path) -> Result<()> {
        run_jar(&self.jar_path(), args, log_name, tmp_dir)
    }
}

#[derive(Debug, Clone)]
struct UberApkSigner;

impl UberApkSigner {
    fn new() -> Self {
        Self
    }

    fn version_name(&self) -> String {
        format!("v{UBER_APK_SIGNER_VERSION}")
    }

    fn jar_path(&self) -> PathBuf {
        cache_path(&format!("uber-apk-signer-v{UBER_APK_SIGNER_VERSION}.jar"))
    }

    fn ensure_downloaded(&self) -> Result<()> {
        download_cached(
            &self.jar_path(),
            &format!("https://github.com/patrickfav/uber-apk-signer/releases/download/v{UBER_APK_SIGNER_VERSION}/uber-apk-signer-{UBER_APK_SIGNER_VERSION}.jar"),
        )
    }

    fn sign(&self, input_paths: &[PathBuf], zipalign: bool, tmp_dir: &Path) -> Result<()> {
        let mut args = vec!["--allowResign".into(), "--overwrite".into()];
        if !zipalign {
            args.push("--skipZipAlign".into());
        }
        for path in input_paths {
            args.push("--apks".into());
            args.push(path.display().to_string());
        }
        run_jar(&self.jar_path(), &args, "signing", tmp_dir)
    }
}

fn run_jar(jar: &Path, args: &[String], log_name: &str, tmp_dir: &Path) -> Result<()> {
    let logs_dir = tmp_dir.join("logs");
    fs::create_dir_all(&logs_dir)?;
    let log_path = logs_dir.join(format!("{log_name}.log"));
    let output = Command::new("java")
        .arg("-jar")
        .arg(jar)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run java -jar {}", jar.display()))?;
    let mut combined = Vec::new();
    combined.extend_from_slice(&output.stdout);
    combined.extend_from_slice(&output.stderr);
    fs::write(&log_path, &combined)?;
    io::stdout().write_all(&output.stdout).ok();
    if !output.status.success() {
        let failed_path = logs_dir.join(format!("{log_name}.failed.log"));
        fs::rename(&log_path, &failed_path).ok();
        bail!(
            "Command failed (see {}):\n{}",
            failed_path.display(),
            String::from_utf8_lossy(&combined)
        );
    }
    Ok(())
}

fn cache_path(name: &str) -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| std::env::temp_dir().join("apk-mitm-cache"))
        .join("apk-mitm")
        .join(name)
}

fn download_cached(path: &Path, url: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    println!("\n    Downloading {url}");
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("jar.dl");
    let mut response = reqwest::blocking::get(url)?.error_for_status()?;
    let mut file = File::create(&tmp)?;
    io::copy(&mut response, &mut file)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn apply_patches(decode_dir: &Path, options: &Options) -> Result<bool> {
    let uses_app_bundle = modify_manifest(
        &decode_dir.join("AndroidManifest.xml"),
        options.debuggable,
        options.maps_api_key.as_deref(),
    )?;
    if let Some(certificate) = &options.certificate_path {
        copy_certificate_file(decode_dir, certificate)?;
    }
    create_network_security_config(
        &decode_dir.join("res/xml/nsc_mitm.xml"),
        options.certificate_path.as_deref(),
    )?;
    disable_certificate_pinning(decode_dir)?;
    Ok(uses_app_bundle)
}

fn modify_manifest(path: &Path, debuggable: bool, maps_api_key: Option<&str>) -> Result<bool> {
    let mut content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let uses_app_bundle = content.contains("android:name=\"com.android.vending.splits\"")
        || content.contains("android:name='com.android.vending.splits'");

    content = set_application_attr(&content, "android:networkSecurityConfig", "@xml/nsc_mitm")?;
    if debuggable {
        content = set_application_attr(&content, "android:debuggable", "true")?;
    }
    if let Some(key) = maps_api_key {
        content = replace_maps_api_keys(&content, key)?;
    }
    fs::write(path, content)?;
    Ok(uses_app_bundle)
}

fn set_application_attr(content: &str, name: &str, value: &str) -> Result<String> {
    let caps = APPLICATION_TAG_RE
        .captures(content)
        .ok_or_else(|| anyhow!("AndroidManifest.xml has no <application> tag"))?;
    let whole = caps.get(0).unwrap().as_str();
    let attrs = caps.name("attrs").unwrap().as_str();
    let attr_re = Regex::new(&format!(
        r#"\s{}\s*=\s*(?:\"[^\"]*\"|'[^']*')"#,
        regex::escape(name)
    ))?;
    let new_attrs = if attr_re.is_match(attrs) {
        attr_re
            .replace(attrs, format!(" {name}=\"{value}\""))
            .to_string()
    } else {
        format!("{attrs} {name}=\"{value}\"")
    };
    let replacement = format!(
        "<application{}{}>",
        new_attrs,
        caps.name("self").map(|m| m.as_str()).unwrap_or("")
    );
    Ok(content.replacen(whole, &replacement, 1))
}

fn replace_maps_api_keys(content: &str, key: &str) -> Result<String> {
    let mut out = String::with_capacity(content.len());
    let mut last = 0;
    for caps in META_DATA_TAG_RE.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let tag = whole.as_str();
        if tag.contains("android:name=\"com.google.android.maps.v2.API_KEY\"")
            || tag.contains("android:name='com.google.android.maps.v2.API_KEY'")
            || tag.contains("android:name=\"com.google.android.geo.API_KEY\"")
            || tag.contains("android:name='com.google.android.geo.API_KEY'")
        {
            out.push_str(&content[last..whole.start()]);
            let attrs = caps.name("attrs").unwrap().as_str();
            let new_attrs = if META_DATA_VALUE_RE.is_match(attrs) {
                META_DATA_VALUE_RE
                    .replace(attrs, format!(" android:value=\"{key}\""))
                    .to_string()
            } else {
                format!("{attrs} android:value=\"{key}\"")
            };
            out.push_str(&format!(
                "<meta-data{}{}>",
                new_attrs,
                caps.name("self").map(|m| m.as_str()).unwrap_or("")
            ));
            last = whole.end();
        }
    }
    out.push_str(&content[last..]);
    Ok(out)
}

fn copy_certificate_file(decode_dir: &Path, source: &Path) -> Result<()> {
    let raw_dir = decode_dir.join("res/raw");
    fs::create_dir_all(&raw_dir)?;
    fs::copy(source, raw_dir.join(source.file_name().unwrap()))?;
    Ok(())
}

fn create_network_security_config(path: &Path, certificate_path: Option<&Path>) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let certificate_block = certificate_path
        .map(|p| {
            let file_name = p.file_name().and_then(OsStr::to_str).unwrap_or("certificate");
            let resource_name = file_name.rsplit_once('.').map(|(name, _)| name).unwrap_or(file_name);
            format!("\n\n        <!-- Allow specific certificate -->\n        <certificates src=\"@raw/{resource_name}\" />\n")
        })
        .unwrap_or_default();
    let config = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n  <!-- Intentionally lax Network Security Configuration (generated by apk-mitm) -->\n  <network-security-config>\n    <!-- Allow cleartext traffic -->\n    <base-config cleartextTrafficPermitted=\"true\">\n      <trust-anchors>\n        <!-- Allow user-added (proxy) certificates -->\n        <certificates src=\"user\" />{certificate_block}        <certificates src=\"system\" />\n      </trust-anchors>\n    </base-config>\n  </network-security-config>"
    );
    fs::write(path, config)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum SelectorType {
    Class,
    Interface,
}

struct SmaliPatch {
    selector_type: SelectorType,
    selector_name: &'static str,
    methods: &'static [SmaliMethodPatch],
}

struct SmaliMethodPatch {
    name: &'static str,
    pattern: &'static LazyLock<Regex>,
    replacement_lines: &'static [&'static str],
}

fn smali_method_regex(signature: &str) -> Regex {
    Regex::new(&format!(
        r"(?s)(\.method public (?:final )?{})\n(.+?)\n(\.end method)",
        regex::escape(signature)
    ))
    .expect("valid smali method regex")
}

static X509_CHECK_CLIENT_TRUSTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    smali_method_regex(
        "checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
    )
});
static X509_CHECK_SERVER_TRUSTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    smali_method_regex(
        "checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
    )
});
static X509_GET_ACCEPTED_ISSUERS_RE: LazyLock<Regex> = LazyLock::new(|| {
    smali_method_regex("getAcceptedIssuers()[Ljava/security/cert/X509Certificate;")
});
static HOSTNAME_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| smali_method_regex("verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z"));
static CERT_PINNER_CHECK_LIST_RE: LazyLock<Regex> =
    LazyLock::new(|| smali_method_regex("check(Ljava/lang/String;Ljava/util/List;)V"));
static CERT_PINNER_CHECK_OKHTTP_RE: LazyLock<Regex> = LazyLock::new(|| {
    smali_method_regex("check$okhttp(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V")
});

const RETURN_VOID: &[&str] = &[".locals 0", "return-void"];
const RETURN_TRUE: &[&str] = &[".locals 1", "const/4 v0, 0x1", "return v0"];
const RETURN_EMPTY_CERT_ARRAY: &[&str] = &[
    ".locals 1",
    "const/4 v0, 0x0",
    "new-array v0, v0, [Ljava/security/cert/X509Certificate;",
    "return-object v0",
];

const X509_METHODS: &[SmaliMethodPatch] = &[
    SmaliMethodPatch {
        name: "X509TrustManager#checkClientTrusted (javax)",
        pattern: &X509_CHECK_CLIENT_TRUSTED_RE,
        replacement_lines: RETURN_VOID,
    },
    SmaliMethodPatch {
        name: "X509TrustManager#checkServerTrusted (javax)",
        pattern: &X509_CHECK_SERVER_TRUSTED_RE,
        replacement_lines: RETURN_VOID,
    },
    SmaliMethodPatch {
        name: "X509TrustManager#getAcceptedIssuers (javax)",
        pattern: &X509_GET_ACCEPTED_ISSUERS_RE,
        replacement_lines: RETURN_EMPTY_CERT_ARRAY,
    },
];
const HOSTNAME_METHODS: &[SmaliMethodPatch] = &[SmaliMethodPatch {
    name: "HostnameVerifier#verify (javax)",
    pattern: &HOSTNAME_VERIFY_RE,
    replacement_lines: RETURN_TRUE,
}];
const OKHTTP2_METHODS: &[SmaliMethodPatch] = &[SmaliMethodPatch {
    name: "CertificatePinner#check (OkHttp 2.5)",
    pattern: &CERT_PINNER_CHECK_LIST_RE,
    replacement_lines: RETURN_VOID,
}];
const OKHTTP3_METHODS: &[SmaliMethodPatch] = &[
    SmaliMethodPatch {
        name: "CertificatePinner#check (OkHttp 3.x)",
        pattern: &CERT_PINNER_CHECK_LIST_RE,
        replacement_lines: RETURN_VOID,
    },
    SmaliMethodPatch {
        name: "CertificatePinner#check (OkHttp 4.2)",
        pattern: &CERT_PINNER_CHECK_OKHTTP_RE,
        replacement_lines: RETURN_VOID,
    },
];
const SMALI_PATCHES: &[SmaliPatch] = &[
    SmaliPatch {
        selector_type: SelectorType::Interface,
        selector_name: "javax/net/ssl/X509TrustManager",
        methods: X509_METHODS,
    },
    SmaliPatch {
        selector_type: SelectorType::Interface,
        selector_name: "javax/net/ssl/HostnameVerifier",
        methods: HOSTNAME_METHODS,
    },
    SmaliPatch {
        selector_type: SelectorType::Class,
        selector_name: "com/squareup/okhttp/CertificatePinner",
        methods: OKHTTP2_METHODS,
    },
    SmaliPatch {
        selector_type: SelectorType::Class,
        selector_name: "okhttp3/CertificatePinner",
        methods: OKHTTP3_METHODS,
    },
];

#[derive(Debug)]
struct SmaliHead {
    name: String,
    implements: Vec<String>,
    is_interface: bool,
}

fn disable_certificate_pinning(decode_dir: &Path) -> Result<bool> {
    println!("\n    Scanning Smali files...");
    let mut found = false;
    for entry in WalkDir::new(decode_dir).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() || entry.path().extension() != Some(OsStr::new("smali")) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(decode_dir)
            .unwrap_or(entry.path());
        if !rel
            .components()
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .is_some_and(|s| s.starts_with("smali"))
        {
            continue;
        }
        if process_smali_file(entry.path())? {
            found = true;
        }
    }
    if !found {
        println!("    No certificate pinning logic found.");
    }
    Ok(found)
}

fn process_smali_file(path: &Path) -> Result<bool> {
    let original = fs::read_to_string(path)?;
    let normalized = if cfg!(windows) {
        Cow::Owned(original.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(original.as_str())
    };
    let head = parse_smali_head(&normalized)?;
    if head.is_interface {
        return Ok(false);
    }
    let applicable_patches: Vec<_> = SMALI_PATCHES
        .iter()
        .filter(|patch| selector_matches(patch, &head))
        .collect();
    if applicable_patches.is_empty() {
        return Ok(false);
    }

    let mut patched = normalized.into_owned();
    let mut changed = false;
    for patch in applicable_patches {
        for method in patch.methods {
            let (new_content, did_patch) = patch_smali_method(&patched, method)?;
            if did_patch {
                println!("    {}: Applied {} patch", head.name, method.name);
                patched = new_content;
                changed = true;
            }
        }
    }
    if changed {
        if cfg!(windows) {
            patched = patched.replace('\n', "\r\n");
        }
        fs::write(path, patched)?;
    }
    Ok(changed)
}

fn parse_smali_head(content: &str) -> Result<SmaliHead> {
    let caps = SMALI_CLASS_RE
        .captures(content)
        .ok_or_else(|| anyhow!("Smali file has no .class line"))?;
    let keywords = caps.name("keywords").map(|m| m.as_str()).unwrap_or("");
    let name = caps.name("name").unwrap().as_str().to_string();
    let implements = SMALI_IMPLEMENTS_RE
        .captures_iter(content)
        .map(|caps| caps.name("name").unwrap().as_str().to_string())
        .collect();
    let is_interface = keywords.split_whitespace().any(|part| part == "interface");
    Ok(SmaliHead {
        name,
        implements,
        is_interface,
    })
}

fn selector_matches(patch: &SmaliPatch, head: &SmaliHead) -> bool {
    match patch.selector_type {
        SelectorType::Class => patch.selector_name == head.name,
        SelectorType::Interface => head
            .implements
            .iter()
            .any(|name| name == patch.selector_name),
    }
}

fn patch_smali_method(content: &str, method: &SmaliMethodPatch) -> Result<(String, bool)> {
    let mut changed = false;
    let result = method
        .pattern
        .replace_all(content, |caps: &regex::Captures| {
            changed = true;
            let body_lines = caps[2]
                .split('\n')
                .map(|line| line.strip_prefix("    ").unwrap_or(line));
            let mut patched_body: Vec<String> =
                vec!["# inserted by apk-mitm to disable certificate pinning".into()];
            patched_body.extend(method.replacement_lines.iter().map(|line| line.to_string()));
            patched_body.push(String::new());
            patched_body.push("# commented out by apk-mitm to disable old method body".into());
            patched_body.push("# ".into());
            patched_body.extend(body_lines.map(|line| format!("# {line}")));

            let body = patched_body
                .into_iter()
                .map(|line| format!("    {}", line).trim_end().to_string())
                .collect::<Vec<_>>()
                .join("\n");
            format!("{}\n{}\n{}", &caps[1], body, &caps[3])
        });
    Ok((result.into_owned(), changed))
}

fn unzip_file(input: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    let file = File::open(input)?;
    let mut archive = zip::ZipArchive::new(file)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => output_dir.join(path),
            None => continue,
        };
        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

fn zip_dir(input_dir: &Path, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut buffer = Vec::new();
    for entry in WalkDir::new(input_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let name = path
            .strip_prefix(input_dir)?
            .to_string_lossy()
            .replace('\\', "/");
        if name.is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            zip.add_directory(format!("{name}/"), options)?;
        } else {
            zip.start_file(name, options)?;
            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        }
    }
    zip.finish()?;
    Ok(())
}

fn find_xapk_base_apk(bundle_dir: &Path) -> Result<PathBuf> {
    let manifest = fs::read_to_string(bundle_dir.join("manifest.json"))?;
    let json: Value = serde_json::from_str(&manifest)?;
    if let Some(split_apks) = json.get("split_apks").and_then(Value::as_array) {
        if let Some(file) = split_apks
            .iter()
            .find(|apk| apk.get("id") == Some(&Value::String("base".into())))
            .and_then(|apk| apk.get("file"))
            .and_then(Value::as_str)
        {
            return Ok(bundle_dir.join(file));
        }
    }
    let package = json
        .get("package_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("XAPK manifest has no package_name"))?;
    Ok(bundle_dir.join(format!("{package}.apk")))
}

fn show_app_bundle_warning() {
    println!(
        "\n  WARNING\n\n  This app seems to use Android App Bundle split APKs. You may run into\n  installation problems because only one APK was patched. Supply a .xapk or\n  .apks file containing all APKs to patch the bundle.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_okhttp3_certificate_pinner() {
        let smali = r#".class public final Lokhttp3/CertificatePinner;
.super Ljava/lang/Object;

.method public check(Ljava/lang/String;Ljava/util/List;)V
    .locals 2
    invoke-static {}, Lfoo/Bar;->baz()V
    return-void
.end method
"#;
        let method = &OKHTTP3_METHODS[0];
        let (patched, changed) = patch_smali_method(smali, method).unwrap();
        assert!(changed);
        assert!(patched.contains("# inserted by apk-mitm to disable certificate pinning"));
        assert!(patched.contains("    .locals 0\n    return-void"));
        assert!(patched.contains("# invoke-static {}, Lfoo/Bar;->baz()V"));
    }

    #[test]
    fn parses_smali_head() {
        let head = parse_smali_head(".class public Lx/Y;\n.super Ljava/lang/Object;\n.implements Ljavax/net/ssl/HostnameVerifier;\n").unwrap();
        assert_eq!(head.name, "x/Y");
        assert_eq!(head.implements, vec!["javax/net/ssl/HostnameVerifier"]);
        assert!(!head.is_interface);
    }

    #[test]
    fn adds_manifest_attrs_and_maps_key() {
        let input = r#"<manifest><application android:label="App"><meta-data android:name="com.google.android.geo.API_KEY" android:value="old" /></application></manifest>"#;
        let output =
            set_application_attr(input, "android:networkSecurityConfig", "@xml/nsc_mitm").unwrap();
        let output = set_application_attr(&output, "android:debuggable", "true").unwrap();
        let output = replace_maps_api_keys(&output, "new-key").unwrap();
        assert!(output.contains("android:networkSecurityConfig=\"@xml/nsc_mitm\""));
        assert!(output.contains("android:debuggable=\"true\""));
        assert!(output.contains("android:value=\"new-key\""));
    }
}
