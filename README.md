<div align="center">

# apk-mitm

**Patch Android apps for HTTPS inspection — fast, repeatable, and split-aware.**

[![Rust](https://img.shields.io/badge/Rust-2021-000000?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Android](https://img.shields.io/badge/Android-APK-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/)
[![Java](https://img.shields.io/badge/Java-8%2B-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
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

**Requirements:** Java 8+ and a Rust toolchain.

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
| `--debuggable` | Mark the app as debuggable |
| `--certificate <file>` | Add a PEM or DER certificate |
| `--maps-api-key <key>` | Replace Google Maps API keys |
| `--apktool <jar>` | Use a custom Apktool JAR |
| `--tmp-dir <path>` | Choose the temporary directory |
| `--keep-tmp-dir` | Preserve temporary files for inspection |
| `--wait` | Pause before rebuilding |

Run `apk-mitm --help` for complete usage details.

## 🧰 Toolchain

Dependencies are downloaded to the OS cache on first use.

| Tool | Purpose |
|---|---|
| [APKEditor](https://github.com/REAndroid/APKEditor) | Merge split APK bundles |
| [Apktool](https://apktool.org/) | Decode and rebuild APKs |
| [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) | Zip-align and sign output APKs |

## 📄 License

Released under the [MIT License](LICENSE).
