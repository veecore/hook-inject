use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(feature = "download-devkit")]
mod devkit;

#[cfg(feature = "download-devkit")]
pub use devkit::{
    detect_devkit_platform, download_devkit, resolve_devkit_platform, resolve_devkit_versions,
};

#[cfg(feature = "build-utils")]
pub use pkg_config::Library as PkgConfigLibrary;

//=== Error types ===

#[derive(Debug)]
pub struct BuildError {
    message: String,
}

impl BuildError {
    fn new<M: AsRef<str>>(msg: M) -> Self {
        Self {
            message: msg.as_ref().to_string(),
        }
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BuildError {}

type Result<T> = std::result::Result<T, BuildError>;

//=== Build helpers ===

#[cfg(feature = "build-utils")]
pub fn probe_pkg(name: &str) -> PkgConfigLibrary {
    pkg_config::Config::new()
        .probe(name)
        .unwrap_or_else(|_| panic!("missing pkg-config dependency: {name}"))
}

#[derive(Debug)]
pub struct CdylibInfo {
    pub path: PathBuf,
    pub entrypoint: Option<String>,
    pub data: Option<String>,
}

#[derive(Debug)]
pub struct CrateMetadata {
    pub package_name: String,
    pub entrypoint: Option<String>,
    pub data: Option<String>,
    pub manifest_path: PathBuf,
    pub crate_dir: PathBuf,
    pub target_dir: PathBuf,
    pub cdylib_filename: String,
    pub cdylib_path: Option<PathBuf>,
}

// TODO: H
pub fn read_cdylib_file(crate_path: &Path) -> Option<Result<CdylibInfo>> {
    let meta = match read_crate_metadata(crate_path)? {
        Ok(meta) => meta,
        Err(err) => return Some(Err(err)),
    };

    Some(Ok(CdylibInfo {
        path: meta.cdylib_path?,
        entrypoint: meta.entrypoint,
        data: meta.data,
    }))
}

//=== Metadata helpers ===

/// Read cdylib metadata from a crate manifest without building it.
pub fn read_crate_metadata<P: AsRef<Path>>(crate_path: P) -> Option<Result<CrateMetadata>> {
    let manifest_path = if crate_path.as_ref().is_dir() {
        crate_path.as_ref().join("Cargo.toml")
    } else {
        crate_path.as_ref().to_path_buf()
    };

    if !manifest_path.is_file() {
        return None;
    }

    let manifest_src = match std::fs::read_to_string(&manifest_path) {
        Ok(src) => src,
        Err(e) => {
            return Some(Err(BuildError::new(format!(
                "failed to read Cargo.toml: {e}"
            ))));
        }
    };
    let manifest: toml::Value = match toml::from_str(&manifest_src) {
        Ok(value) => value,
        Err(e) => {
            return Some(Err(BuildError::new(format!(
                "failed to parse Cargo.toml: {e}"
            ))));
        }
    };

    let package = manifest
        .get("package")
        .ok_or_else(|| BuildError::new("missing [package] section"));
    let package = match package {
        Ok(value) => value,
        Err(err) => return Some(Err(err)),
    };
    let package_name = package
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BuildError::new("missing [package].name"));
    let package_name = match package_name {
        Ok(value) => value,
        Err(err) => return Some(Err(err)),
    };

    let is_cdylib = manifest
        .get("lib")
        .and_then(|l| l.get("crate-type"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("cdylib")))
        .unwrap_or(false);

    if !is_cdylib {
        return Some(Err(BuildError::new(
            "crate is not configured as cdylib; add [lib] crate-type = [\"cdylib\"]",
        )));
    }

    let meta = package.get("metadata").and_then(|m| m.get("hook-inject"));
    let entrypoint = meta
        .and_then(|m| m.get("entrypoint"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let data = meta
        .and_then(|m| m.get("data"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let crate_dir = match manifest_path.parent() {
        Some(dir) => dir.to_path_buf(),
        None => return Some(Err(BuildError::new("invalid manifest path"))),
    };
    let target_dir = resolve_target_dir(&crate_dir);
    let cdylib_filename = library_filename(package_name);
    let cdylib_path = find_cdylib_in_targets(&crate_dir, &target_dir, &cdylib_filename);

    Some(Ok(CrateMetadata {
        package_name: package_name.to_string(),
        entrypoint,
        data,
        manifest_path,
        crate_dir,
        target_dir,
        cdylib_filename,
        cdylib_path,
    }))
}

/// Build a cdylib and return its resolved path and metadata.
///
/// # Examples
/// ```no_run
/// use hook_inject_build::build_cdylib;
///
/// let info = build_cdylib("path/to/agent-crate").unwrap();
/// ```
pub fn build_cdylib<P: AsRef<Path>>(crate_path: P) -> Result<CdylibInfo> {
    let meta = match read_crate_metadata(crate_path) {
        Some(Ok(meta)) => meta,
        Some(Err(err)) => return Err(err),
        None => return Err(BuildError::new("missing Cargo.toml")),
    };
    let manifest_path = meta.manifest_path.clone();
    let status = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .status()
        .map_err(|e| BuildError::new(format!("failed to invoke cargo: {e}")))?;
    if !status.success() {
        return Err(BuildError::new("cargo build failed"));
    }

    let path = find_cdylib_in_targets(&meta.crate_dir, &meta.target_dir, &meta.cdylib_filename)
        .ok_or_else(|| BuildError::new("cdylib not found after build"))?;

    Ok(CdylibInfo {
        path,
        entrypoint: meta.entrypoint,
        data: meta.data,
    })
}

/// Build the platform-specific filename for a cdylib crate.
pub fn library_filename(crate_name: &str) -> String {
    let name = crate_name.replace('-', "_");

    if cfg!(windows) {
        format!("{name}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{name}.dylib")
    } else {
        format!("lib{name}.so")
    }
}

fn resolve_target_dir(crate_dir: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate_dir.join("target"))
}

fn find_cdylib_in_targets(crate_dir: &Path, target_dir: &Path, filename: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    candidates.push(target_dir.to_path_buf());

    let mut cur = crate_dir;
    for _ in 0..4 {
        candidates.push(cur.join("target"));
        if let Some(parent) = cur.parent() {
            cur = parent;
        } else {
            break;
        }
    }

    for root in candidates {
        let dirs = [root.join("release"), root.join("debug")];
        for dir in dirs {
            let candidate = dir.join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}
