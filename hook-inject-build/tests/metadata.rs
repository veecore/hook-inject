use std::path::PathBuf;

use hook_inject_build::{library_filename, read_crate_metadata};

#[test]
fn reads_fixture_metadata() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let fixture = root.join("fixtures/agent");

    let meta = read_crate_metadata(fixture)
        .expect("read fixture metadata")
        .expect("fixture metadata ok");
    assert_eq!(meta.package_name, "hook-inject-fixture-agent");
    assert_eq!(meta.entrypoint.as_deref(), Some("hook_inject_entry"));
    assert_eq!(meta.data.as_deref(), Some("fixture"));
}

#[test]
fn library_filename_formats() {
    let name = library_filename("foo-bar");
    if cfg!(windows) {
        assert_eq!(name, "foo_bar.dll");
    } else if cfg!(target_os = "macos") {
        assert_eq!(name, "libfoo_bar.dylib");
    } else {
        assert_eq!(name, "libfoo_bar.so");
    }
}
