use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{BuildError, Result};

//=== Platform resolution ===

/// Detect the current platform string used by Frida devkit assets.
pub fn detect_devkit_platform() -> Result<String> {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| env::consts::OS.into());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| env::consts::ARCH.into());

    let platform = match (os.as_str(), arch.as_str()) {
        ("macos", "aarch64") | ("macos", "arm64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x86_64",
        ("linux", "aarch64") | ("linux", "arm64") => "linux-arm64",
        ("linux", "x86_64") => "linux-x86_64",
        ("windows", "aarch64") | ("windows", "arm64") => "windows-arm64",
        ("windows", "x86_64") => "windows-x86_64",
        _ => {
            return Err(BuildError::new(format!(
                "unsupported platform for devkit download: {os}-{arch}"
            )));
        }
    };

    Ok(platform.to_string())
}

/// Resolve the devkit platform string, honoring HOOK_INJECT_DEVKIT_PLATFORM.
pub fn resolve_devkit_platform() -> Result<String> {
    if let Ok(platform) = env::var("HOOK_INJECT_DEVKIT_PLATFORM") {
        return Ok(platform);
    }
    detect_devkit_platform()
}

//=== Version resolution ===

/// Resolve the preferred devkit versions list.
///
/// The default version is always included first. If auto-detection is enabled
/// and the detected version is in the supported list, it is added as a fallback.
pub fn resolve_devkit_versions(default: &str, supported: &[&str]) -> (Vec<String>, bool) {
    if let Ok(version) = env::var("HOOK_INJECT_DEVKIT_VERSION") {
        return (vec![version], false);
    }

    let mut versions = Vec::new();
    if !default.is_empty() {
        versions.push(default.to_string());
    }

    for &version in supported {
        if !versions.iter().any(|v| v == version) {
            versions.push(version.to_string());
        }
    }

    #[cfg(feature = "auto-detect")]
    {
        let only_default =
            supported.len() <= 1 && supported.first().map(|v| *v == default).unwrap_or(true);
        if !only_default
            && let Some(version) = detect_frida_version()
            && supported.iter().any(|&v| v == version)
            && !versions.iter().any(|v| v == &version)
        {
            versions.push(version);
        }
    }

    (versions, true)
}

/// Download and extract a Frida devkit archive into `out_dir`.
///
/// This helper uses `curl` + `tar` under the hood.
pub fn download_devkit<P: AsRef<Path>>(
    version: &str,
    out_dir: P,
    platform: Option<&str>,
) -> Result<PathBuf> {
    let platform = match platform {
        Some(p) => p.to_string(),
        None => detect_devkit_platform()?,
    };

    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)
        .map_err(|e| BuildError::new(format!("failed to create devkit dir: {e}")))?;

    // Windows devkits have shipped as both tar.xz and zip across releases.
    let extensions: &[&str] = if platform.starts_with("windows-") {
        &["tar.xz", "zip"]
    } else {
        &["tar.xz"]
    };

    let mut last_error = None;
    for ext in extensions {
        let filename = format!("frida-core-devkit-{version}-{platform}.{ext}");
        let archive = out_dir.join(&filename);
        let url = format!("https://github.com/frida/frida/releases/download/{version}/{filename}");

        let result = download_and_extract(&url, &archive, out_dir, ext);
        match result {
            Ok(()) => return Ok(out_dir.to_path_buf()),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| BuildError::new("failed to download devkit archive (no candidates)")))
}

fn download_and_extract(url: &str, archive: &Path, out_dir: &Path, ext: &str) -> Result<()> {
    run(Command::new("curl")
        .args(["-fL", "-o"])
        .arg(archive)
        .arg(url))?;

    if ext == "zip" {
        let cmd = format!(
            "Expand-Archive -Force -Path '{}' -DestinationPath '{}'",
            archive.display(),
            out_dir.display()
        );
        run(Command::new("powershell").args(["-NoProfile", "-Command", &cmd]))?;
    } else {
        run(Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(out_dir))?;
    }

    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| BuildError::new(format!("failed to run {:?}: {e}", cmd)))?;
    if !status.success() {
        return Err(BuildError::new(format!("command failed ({:?})", cmd)));
    }
    Ok(())
}

//=== Auto-detection ===

#[cfg(feature = "auto-detect")]
fn detect_frida_version() -> Option<String> {
    probe_frida_command()
}

#[cfg(feature = "auto-detect")]
fn probe_frida_command() -> Option<String> {
    let output = Command::new("frida").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_version(&output.stdout)
}

#[cfg(feature = "auto-detect")]
fn parse_version(output: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(output);
    let line = raw.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}
