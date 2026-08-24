use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use regex::Regex;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use tempfile::TempDir;
use walkdir::WalkDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const APKTOOL_VERSION: &str = "2.9.3";
const UBER_APK_SIGNER_VERSION: &str = "1.3.0";
const APKEDITOR_VERSION: &str = "1.4.3";

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

    /// Decode Smali and apply pinning patches (slower, broader coverage)
    #[arg(long = "full-smali")]
    full_smali: bool,

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
    AppBundle,
}

#[derive(Debug)]
struct TaskInfo {
    kind: TaskKind,
    skip_decode: bool,
    output_path: PathBuf,
    output_name: String,
}

#[derive(Debug)]
struct Options {
    input_path: PathBuf,
    output_path: PathBuf,
    tmp_dir: PathBuf,
    skip_patches: bool,
    full_smali: bool,
    certificate_path: Option<PathBuf>,
    maps_api_key: Option<String>,
    apktool: Apktool,
    signer: UberApkSigner,
    wait: bool,
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
    if info.kind == TaskKind::AppBundle {
        println!("  ├ uber-apk-signer {}", signer.version_name());
        println!("  ╰ apk-editor {}", ApkEditor::new().version_name());
    } else {
        println!("  ╰ uber-apk-signer {}", signer.version_name());
    }
    println!();
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
        full_smali: args.full_smali,
        certificate_path,
        maps_api_key: args.maps_api_key,
        apktool,
        signer,
        wait: args.wait,
        debuggable: args.debuggable,
        skip_decode: info.skip_decode,
    };

    let uses_app_bundle = match info.kind {
        TaskKind::Apk => patch_apk(&options)?,
        TaskKind::AppBundle => patch_app_bundle(&options)?,
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
    let kind;

    if metadata.is_dir() {
        kind = TaskKind::Apk;
        skip_decode = true;
        if !input_path.join("apktool.yml").exists() {
            bail!("No \"apktool.yml\" file found inside the input directory! Make sure to specify a directory created by \"apktool decode\".");
        }
    } else {
        let ext = input_path.extension().and_then(OsStr::to_str).unwrap_or("");
        kind = match ext {
            "apk" => TaskKind::Apk,
            "xapk" | "apks" | "zip" => TaskKind::AppBundle,
            _ => bail!("Unsupported file type. Supported extensions: .apk, .xapk, .apks, .zip, or a decoded apktool directory."),
        };
    }

    let base_name = input_path
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("Could not determine input file name"))?;
    // Bundle inputs are merged into a standalone universal APK, so every
    // input type produces a <stem>-patched.apk next to the input.
    let output_name = format!("{base_name}-patched.apk");
    let output_path = input_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&output_name);

    Ok(TaskInfo {
        kind,
        skip_decode,
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
            options.apktool.decode(
                &options.input_path,
                &decode_dir,
                options.full_smali,
                &options.tmp_dir,
            )
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

fn patch_app_bundle(options: &Options) -> Result<bool> {
    step("Checking prerequisites", || check_prerequisites(options))?;

    let merged_apk_path = options.tmp_dir.join("merged.apk");
    step("Merging splits into universal APK", || {
        let apk_editor = ApkEditor::new();
        apk_editor.ensure_downloaded()?;
        apk_editor.merge(&options.input_path, &merged_apk_path, &options.tmp_dir)
    })?;

    let merged_options = Options {
        input_path: merged_apk_path,
        output_path: options.output_path.clone(),
        tmp_dir: options.tmp_dir.clone(),
        skip_patches: options.skip_patches,
        full_smali: options.full_smali,
        certificate_path: options.certificate_path.clone(),
        maps_api_key: options.maps_api_key.clone(),
        apktool: options.apktool.clone(),
        signer: UberApkSigner::new(),
        wait: options.wait,
        debuggable: options.debuggable,
        skip_decode: false,
    };

    patch_apk(&merged_options)
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
    options.apktool.ensure_downloaded()?;
    options.signer.ensure_downloaded()?;
    Ok(())
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

    fn decode(
        &self,
        input: &Path,
        output: &Path,
        decode_sources: bool,
        tmp_dir: &Path,
    ) -> Result<()> {
        let args = self.decode_args(input, output, decode_sources);
        self.run(&args, "decoding", tmp_dir)
    }

    fn decode_args(&self, input: &Path, output: &Path, decode_sources: bool) -> Vec<String> {
        let mut args = vec![
            "decode".into(),
            input.display().to_string(),
            "--output".into(),
            output.display().to_string(),
            "--frame-path".into(),
            self.framework_path.display().to_string(),
        ];
        if !decode_sources {
            args.push("--no-src".into());
        }
        args
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

#[derive(Debug, Clone)]
struct ApkEditor;

impl ApkEditor {
    fn new() -> Self {
        Self
    }

    fn version_name(&self) -> String {
        format!("v{APKEDITOR_VERSION}")
    }

    fn jar_path(&self) -> PathBuf {
        cache_path(&format!("APKEditor-{APKEDITOR_VERSION}.jar"))
    }

    fn ensure_downloaded(&self) -> Result<()> {
        download_cached(
            &self.jar_path(),
            &format!("https://github.com/REAndroid/APKEditor/releases/download/V{APKEDITOR_VERSION}/APKEditor-{APKEDITOR_VERSION}.jar"),
        )
    }

    fn merge(&self, input: &Path, output: &Path, tmp_dir: &Path) -> Result<()> {
        run_jar(
            &self.jar_path(),
            &[
                "m".into(),
                "-i".into(),
                input.display().to_string(),
                "-o".into(),
                output.display().to_string(),
            ],
            "merging",
            tmp_dir,
        )
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
    if options.full_smali {
        disable_certificate_pinning(decode_dir)?;
    }
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
    for root in smali_roots(decode_dir)? {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() || entry.path().extension() != Some(OsStr::new("smali"))
            {
                continue;
            }
            if process_smali_file(entry.path())? {
                found = true;
            }
        }
    }
    if !found {
        println!("    No certificate pinning logic found.");
    }
    Ok(found)
}

fn smali_roots(decode_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for entry in fs::read_dir(decode_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("smali"))
        {
            roots.push(entry.path());
        }
    }
    roots.sort_unstable();
    Ok(roots)
}

fn process_smali_file(path: &Path) -> Result<bool> {
    let head = parse_smali_head_reader(BufReader::new(File::open(path)?))?;
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

    let original = fs::read_to_string(path)?;
    let normalized = if cfg!(windows) {
        Cow::Owned(original.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(original.as_str())
    };
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

#[cfg(test)]
fn parse_smali_head(content: &str) -> Result<SmaliHead> {
    parse_smali_head_reader(BufReader::new(content.as_bytes()))
}

fn parse_smali_head_reader(reader: impl BufRead) -> Result<SmaliHead> {
    let mut name = None;
    let mut implements = Vec::new();
    let mut is_interface = false;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with(".method") {
            break;
        }
        if let Some(declaration) = line.strip_prefix(".class") {
            let mut parts = declaration.split_whitespace();
            let mut class_name = None;
            for part in parts.by_ref() {
                if let Some(value) = smali_type_name(part) {
                    class_name = Some(value.to_string());
                    break;
                }
                if part == "interface" {
                    is_interface = true;
                }
            }
            name = class_name;
        } else if let Some(declaration) = line.strip_prefix(".implements") {
            if let Some(interface_name) = declaration.split_whitespace().find_map(smali_type_name) {
                implements.push(interface_name.to_string());
            }
        }
    }

    Ok(SmaliHead {
        name: name.ok_or_else(|| anyhow!("Smali file has no .class line"))?,
        implements,
        is_interface,
    })
}

fn smali_type_name(value: &str) -> Option<&str> {
    value.strip_prefix('L')?.strip_suffix(';')
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
    fn parses_interface_head_with_crlf_and_stops_at_first_method() {
        let content = concat!(
            ".class public abstract interface Lx/Y;\r\n",
            ".implements Lfoo/First;\r\n",
            ".implements Lfoo/Second;\r\n",
            ".method public test()V\r\n",
            ".implements Lfoo/NotAHeaderDirective;\r\n",
        );
        let head = parse_smali_head(content).unwrap();
        assert_eq!(head.name, "x/Y");
        assert_eq!(head.implements, vec!["foo/First", "foo/Second"]);
        assert!(head.is_interface);
    }

    #[test]
    fn discovers_only_top_level_smali_roots() {
        let temp = tempfile::tempdir().unwrap();
        let smali = temp.path().join("smali");
        let multidex = temp.path().join("smali_classes2");
        fs::create_dir_all(&smali).unwrap();
        fs::create_dir_all(&multidex).unwrap();
        fs::create_dir_all(temp.path().join("res/smali_decoy")).unwrap();
        fs::create_dir_all(temp.path().join("assets")).unwrap();
        fs::write(temp.path().join("smali_file"), b"not a directory").unwrap();

        assert_eq!(smali_roots(temp.path()).unwrap(), vec![smali, multidex]);
    }

    #[test]
    fn non_candidate_smali_does_not_require_valid_method_body_utf8() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("Unrelated.smali");
        let mut content = b".class public Lx/Unrelated;\n.method public test()V\n".to_vec();
        content.push(0xff);
        fs::write(&path, content).unwrap();

        assert!(!process_smali_file(&path).unwrap());
    }

    #[test]
    fn candidate_smali_file_is_fully_patched() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("CertificatePinner.smali");
        fs::write(
            &path,
            ".class public final Lokhttp3/CertificatePinner;\n.method public check(Ljava/lang/String;Ljava/util/List;)V\n    .locals 0\n    return-void\n.end method\n",
        )
        .unwrap();

        assert!(process_smali_file(&path).unwrap());
        let patched = fs::read_to_string(path).unwrap();
        assert!(patched.contains("# inserted by apk-mitm"));
    }

    #[test]
    fn apktool_decode_sources_are_opt_in() {
        let apktool = Apktool::new(
            PathBuf::from("framework"),
            Some(PathBuf::from("apktool.jar")),
        );
        let full_args = apktool.decode_args(Path::new("in.apk"), Path::new("out"), true);
        let default_args = apktool.decode_args(Path::new("in.apk"), Path::new("out"), false);

        assert!(!full_args.iter().any(|arg| arg == "--no-src"));
        assert!(default_args.iter().any(|arg| arg == "--no-src"));
    }

    #[test]
    fn full_smali_is_disabled_by_default_and_can_be_enabled() {
        let default_args = Args::try_parse_from(["apk-mitm", "app.apk"]).unwrap();
        let full_args = Args::try_parse_from(["apk-mitm", "--full-smali", "app.apk"]).unwrap();

        assert!(!default_args.full_smali);
        assert!(full_args.full_smali);
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

    #[test]
    fn bundle_inputs_produce_standalone_patched_apk_output() {
        let temp = tempfile::tempdir().unwrap();
        for ext in ["xapk", "apks", "zip"] {
            let input = temp.path().join(format!("com.example.app.{ext}"));
            fs::write(&input, b"dummy").unwrap();
            let info = determine_task(&input).unwrap();
            assert_eq!(info.kind, TaskKind::AppBundle);
            assert_eq!(info.output_name, "com.example.app-patched.apk");
            assert_eq!(
                info.output_path,
                temp.path().join("com.example.app-patched.apk")
            );
        }
    }

    #[test]
    fn apk_input_produces_patched_apk_output() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("app.apk");
        fs::write(&input, b"dummy").unwrap();
        let info = determine_task(&input).unwrap();
        assert_eq!(info.kind, TaskKind::Apk);
        assert!(!info.skip_decode);
        assert_eq!(info.output_name, "app-patched.apk");
        assert_eq!(info.output_path, temp.path().join("app-patched.apk"));
    }

    #[test]
    fn decoded_directory_produces_patched_apk_output() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("apktool.yml"), b"version: 2.9.3").unwrap();
        let info = determine_task(temp.path()).unwrap();
        assert_eq!(info.kind, TaskKind::Apk);
        assert!(info.skip_decode);
        assert!(info.output_name.ends_with("-patched.apk"));
    }
}
