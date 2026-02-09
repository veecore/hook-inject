use std::env;
use std::path::{Path, PathBuf};

use hook_inject_build::{
    download_devkit, probe_pkg, resolve_devkit_platform, resolve_devkit_versions,
};

// === Configuration ===
const DEFAULT_DEVKIT_VERSION: &str = "17.6.2";
// Explicitly list supported devkit versions to avoid drifting with local installations.
const SUPPORTED_DEVKIT_VERSIONS: &[&str] = &[DEFAULT_DEVKIT_VERSION];

// === Build entrypoint ===
fn main() {
    // Build script change tracking.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=native/frida_shim.c");
    println!("cargo:rerun-if-changed=native/frida_shim.h");
    println!("cargo:rerun-if-changed=native/frida_shim_stub.c");
    println!("cargo:rerun-if-env-changed=HOOK_INJECT_SKIP_FRIDA_BUILD");
    println!("cargo:rerun-if-env-changed=FRIDA_CORE_DEVKIT_DIR");
    println!("cargo:rerun-if-env-changed=HOOK_INJECT_DEVKIT_VERSION");
    println!("cargo:rerun-if-env-changed=HOOK_INJECT_DEVKIT_PLATFORM");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // CI escape hatch: build a stub shim without frida-core or Meson/Ninja.
    if env::var_os("HOOK_INJECT_SKIP_FRIDA_BUILD").is_some() {
        cc::Build::new()
            .file(manifest_dir.join("native/frida_shim_stub.c"))
            .compile("hook_frida_shim_stub");
        return;
    }

    // Allow power users to point at a prebuilt devkit directly.
    if let Some(devkit_dir) = env::var_os("FRIDA_CORE_DEVKIT_DIR") {
        build_with_devkit(&manifest_dir, &PathBuf::from(devkit_dir));
        return;
    }

    // Download a devkit by default to keep setup simple.
    if let Some(devkit_dir) = try_download_devkit(&manifest_dir) {
        build_with_devkit(&manifest_dir, &devkit_dir);
        return;
    }

    panic!(
        "failed to download a frida-core devkit; set FRIDA_CORE_DEVKIT_DIR or run scripts/build_frida_core_devkit.sh"
    );
}

//=== Devkit download ===

fn try_download_devkit(manifest_dir: &Path) -> Option<PathBuf> {
    // Download a devkit into target/ and return the resolved directory.
    let (versions, allow_fallback) =
        resolve_devkit_versions(DEFAULT_DEVKIT_VERSION, SUPPORTED_DEVKIT_VERSIONS);
    let platform = match resolve_devkit_platform() {
        Ok(platform) => platform,
        Err(err) => {
            println!("cargo:warning=devkit platform detection failed: {err}");
            return None;
        }
    };

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("target"));

    for (idx, version) in versions.iter().enumerate() {
        let devkit_dir = target_dir
            .join("frida-devkit")
            .join(version)
            .join(&platform);

        let mut resolved = find_devkit_dir(&devkit_dir);
        if resolved.is_none() {
            match download_devkit(version, &devkit_dir, Some(&platform)) {
                Ok(_) => {}
                Err(err) => {
                    println!("cargo:warning=devkit download failed for {version}: {err}");
                    if allow_fallback && idx + 1 < versions.len() {
                        continue;
                    }
                    return None;
                }
            }
            resolved = find_devkit_dir(&devkit_dir);
        }

        if resolved.is_none() {
            println!(
                "cargo:warning=devkit download succeeded but expected files are missing in {}",
                devkit_dir.display()
            );
            if allow_fallback && idx + 1 < versions.len() {
                continue;
            }
            return None;
        }

        println!(
            "cargo:warning=using frida-core devkit {version} ({platform}) from {}",
            devkit_dir.display()
        );
        return Some(devkit_dir);
    }

    None
}

// === Shim build ===
fn build_with_devkit(manifest_dir: &Path, devkit_dir: &Path) {
    // Use a prebuilt devkit and compile the shim against its headers.
    let (lib_dir, lib_name, header_dir, is_static) =
        find_devkit_dir(devkit_dir).expect("invalid FRIDA_CORE_DEVKIT_DIR");

    emit_devkit_watch(&lib_dir, &header_dir);

    let glib = probe_pkg("glib-2.0");
    let gobject = probe_pkg("gobject-2.0");
    let json_glib = probe_pkg("json-glib-1.0");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!(
        "cargo:rustc-link-lib={}={}",
        if is_static { "static" } else { "dylib" },
        lib_name
    );
    link_system_libs(is_static);

    cc::Build::new()
        .file(manifest_dir.join("native/frida_shim.c"))
        .include(header_dir)
        .includes(&glib.include_paths)
        .includes(&gobject.include_paths)
        .includes(&json_glib.include_paths)
        .compile("hook_frida_shim");
}

// === Devkit helpers ===
fn emit_devkit_watch(lib_dir: &Path, header_dir: &Path) {
    // Keep Cargo rebuilds focused on the devkit artifacts we link against.
    let header = header_dir.join("frida-core.h");
    if header.exists() {
        println!("cargo:rerun-if-changed={}", header.display());
    }

    let candidates = [
        "libfrida-core.a",
        "libfrida-core.so",
        "libfrida-core.dylib",
        "frida-core.lib",
        "frida-core.dll",
    ];

    for candidate in candidates {
        let path = lib_dir.join(candidate);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

// === Linking ===
fn link_system_libs(is_static: bool) {
    // Match Frida's link requirements for each target platform.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| env::consts::OS.to_string());
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();

    if target_os == "linux" {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=resolv");
    }

    if target_vendor == "apple" {
        println!("cargo:rustc-link-lib=bsm");
        println!("cargo:rustc-link-lib=resolv");
        println!("cargo:rustc-link-lib=pthread");
    }

    if target_os == "macos" && is_static {
        for framework in [
            "CoreFoundation",
            "Foundation",
            "AppKit",
            "IOKit",
            "Security",
        ] {
            println!("cargo:rustc-link-lib=framework={}", framework);
        }

        println!("cargo:rustc-link-lib=objc");
    }

    if target_os == "windows" {
        for lib in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
            "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32", "setupapi",
        ] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
}

// === Devkit layout ===
fn find_devkit_dir(dir: &Path) -> Option<(PathBuf, String, PathBuf, bool)> {
    // A devkit directory must contain a header and at least one library.
    let mut header_dir = None;
    let mut lib_dir = None;
    let mut lib_name = None;
    let mut is_static = false;

    let header = dir.join("frida-core.h");
    let dylib = dir.join("libfrida-core.so");
    let dylib_mac = dir.join("libfrida-core.dylib");
    let dll = dir.join("frida-core.dll");
    let dll_lib = dir.join("frida-core.lib");
    let static_lib = dir.join("libfrida-core.a");

    if header.exists() {
        header_dir = Some(dir.to_path_buf());
    }

    if dylib.exists() {
        lib_dir = Some(dir.to_path_buf());
        lib_name = Some("frida-core".to_string());
    } else if dylib_mac.exists() {
        lib_dir = Some(dir.to_path_buf());
        lib_name = Some("frida-core".to_string());
    } else if dll_lib.exists() {
        lib_dir = Some(dir.to_path_buf());
        lib_name = Some("frida-core".to_string());
    } else if dll.exists() {
        lib_dir = Some(dir.to_path_buf());
        lib_name = Some("frida-core".to_string());
    } else if static_lib.exists() {
        lib_dir = Some(dir.to_path_buf());
        lib_name = Some("frida-core".to_string());
        is_static = true;
    }

    match (lib_dir, lib_name, header_dir) {
        (Some(l), Some(n), Some(h)) => Some((l, n, h, is_static)),
        _ => None,
    }
}
