# apk-mitm (Rust rewrite)

A Rust CLI that prepares Android APK/APKS/XAPK files for HTTPS inspection.

It mirrors the original `apk-mitm` flow:

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
apk-mitm <path-to-apk/xapk/apks/decoded-directory>
```

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
