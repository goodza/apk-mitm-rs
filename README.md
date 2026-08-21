# apk-mitm (Rust rewrite)

A Rust CLI that prepares Android APK/XAPK/APKS/ZIP files for HTTPS inspection.

It mirrors the original `apk-mitm` flow:

- merge XAPK/APKS/ZIP split bundles into one universal APK with APKEditor
- decode APKs with Apktool
- replace the app Network Security Configuration
- patch common Smali certificate pinning implementations
- rebuild with Apktool (AAPT2, then AAPT fallback)
- sign with uber-apk-signer

## Build

```sh
cargo build --release
```

## Usage

```sh
apk-mitm <path-to-apk/xapk/apks/zip/decoded-directory>
```

The patched output is always a standalone APK named `<input-name>-patched.apk`,
written next to the input. Bundle inputs (`.xapk`, `.apks`, `.zip`) are first
merged with APKEditor into one universal APK that contains the base APK plus
all density/configuration splits, so split resources resolve correctly when
Apktool decodes and rebuilds the app.

Required tools are downloaded into the OS cache directory on first use:

- apktool v2.9.3
- uber-apk-signer v1.3.0
- APKEditor v1.4.3 (bundle inputs only)

Flags:

```text
--wait                         Wait for manual changes before re-encoding
--tmp-dir <path>                Where temporary files will be stored
--keep-tmp-dir                  Don't delete the temporary directory after patching
--debuggable                    Make the patched app debuggable
--skip-patches                  Don't apply any patches
--apktool <path-to-jar>         Use a custom Apktool JAR
--certificate <path-to-pem/der> Add a specific certificate to network security config
--maps-api-key <api-key>        Replace Google Maps API key meta-data values
```
