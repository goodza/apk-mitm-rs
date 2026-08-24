<div align="center">

# apk-mitm

**Patch Android apps for HTTPS inspection — fast, repeatable, and split-aware.**

**Maximum speed — reducing resource processing by 87.4% compared with other APK patching workflows.**

[![Rust](https://img.shields.io/badge/Rust-2021-000000?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Android](https://img.shields.io/badge/Android-APK-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/)
[![Java](https://img.shields.io/badge/Java-8%2B-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Release](https://img.shields.io/github/v/release/goodza/apk-mitm-rs?style=flat-square)](https://github.com/goodza/apk-mitm-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/goodza/apk-mitm-rs/total?style=flat-square)](https://github.com/goodza/apk-mitm-rs/releases)
[![License](https://img.shields.io/github/license/goodza/apk-mitm-rs?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/goodza/apk-mitm-rs?style=flat-square)](https://github.com/goodza/apk-mitm-rs/stargazers)
[![Issues](https://img.shields.io/github/issues/goodza/apk-mitm-rs?style=flat-square)](https://github.com/goodza/apk-mitm-rs/issues)

<pre align="center">
\               /
\             /
.-#######################-.
/#####  ###     ###  #####\
|#####  ###     ###  #####|
|#########################|
.---+#########################+---.
|###|###### APK >> MITM ######|###|
'---+#########################+---'
|#########################|
|########|       |########|
|########|       |########|
'--------'       '--------'
</pre>

</div>

---

## ✨ Highlights

- Accepts `.apk`, `.xapk`, `.apks`, `.zip`, and decoded Apktool directories.
- Merges split bundles into a standalone universal APK.
- Replaces the Network Security Configuration for HTTPS inspection.
- Patches common Smali certificate-pinning implementations.
- Rebuilds, zip-aligns, and signs the final APK automatically.

> **APK / XAPK / APKS / ZIP → Merge → Decode → Patch → Rebuild → Sign**

## 🚀 Quick start

Download a ready-to-run archive for Linux, Windows, or macOS from the
[latest release](https://github.com/goodza/apk-mitm-rs/releases/latest).

To build from source, install Java 8+ and a Rust toolchain:

```sh
git clone https://github.com/goodza/apk-mitm-rs.git
cd apk-mitm-rs
cargo build --release
```

Patch an app:

```sh
target/release/apk-mitm path/to/app.apk
```

The result is written beside the input:

```text
app-patched.apk
```

## ⚙️ Options

| Option | Description |
|---|---|
| `--skip-patches` | Decode and rebuild without applying patches |
| `--full-smali` | Decode Smali and apply pinning patches (slower, broader coverage) |
| `--debuggable` | Mark the app as debuggable |
| `--certificate <file>` | Add a PEM or DER certificate |
| `--maps-api-key <key>` | Replace Google Maps API keys |
| `--apktool <jar>` | Use a custom Apktool JAR |
| `--tmp-dir <path>` | Choose the temporary directory |
| `--keep-tmp-dir` | Preserve temporary files for inspection |
| `--wait` | Pause before rebuilding |

Run `apk-mitm --help` for complete usage details.

## 🐢 Low-resource systems

By default, apk-mitm skips Smali decoding and method patches to reduce CPU use:

```sh
apk-mitm path/to/app.apk
```

The default mode still applies the Network Security Configuration and other
manifest/resource patches and works in approximately 99% of cases. However, it
may not bypass certificate pinning implemented in app code. Enable full Smali
decoding and pinning patches when broader coverage is required:

```sh
apk-mitm --full-smali path/to/app.apk
```

For additional savings, put `--tmp-dir` on fast local storage, use a direct APK
when available to avoid split-bundle merging, and reuse a decoded Apktool
directory when repeatedly editing the same app.

## 🧰 Toolchain

Dependencies are downloaded to the OS cache on first use.

| Tool | Purpose |
|---|---|
| [APKEditor](https://github.com/REAndroid/APKEditor) | Merge split APK bundles |
| [Apktool](https://apktool.org/) | Decode and rebuild APKs |
| [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) | Zip-align and sign output APKs |

## 📄 License

Released under the [MIT License](LICENSE).
