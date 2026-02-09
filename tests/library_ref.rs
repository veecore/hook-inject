use std::path::PathBuf;

use hook_inject::Library;

#[test]
fn from_path_rejects_dir() {
    let dir = std::env::temp_dir();
    let err = Library::from_path(dir).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("library path must be a file"));
}

#[test]
fn from_crate_finds_fixture_cdylib() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("fixtures/agent");

    let lib = Library::from_crate(fixture.clone()).expect("fixture cdylib should be discoverable");
    assert_eq!(lib.entrypoint().to_str().unwrap(), "hook_inject_entry");
    assert_eq!(lib.data().to_str().unwrap(), "fixture");
}

#[test]
fn from_crate_rejects_non_cdylib() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("fixtures/target");
    let err = Library::from_crate(fixture).unwrap_err();
    assert!(
        err.to_string()
            .contains("crate is not configured as cdylib")
    );
}

#[test]
fn from_crate_rejects_missing_manifest() {
    let tmp = std::env::temp_dir().join("hook-inject-missing-manifest");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create temp dir");
    let err = Library::from_crate(&tmp).unwrap_err();
    assert!(err.to_string().contains("missing Cargo.toml"));
}
