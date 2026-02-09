use std::ffi::CString;

use hook_inject::Library;

#[test]
fn entrypoint_sets_value() {
    let entry = CString::new("entry_fn").expect("cstring");
    let lib = Library::from_bytes(vec![1])
        .expect("library")
        .with_entrypoint(entry.clone());
    assert_eq!(lib.entrypoint().to_bytes(), entry.as_bytes());
}

#[test]
fn data_sets_value() {
    let data = CString::new("payload").expect("cstring");
    let lib = Library::from_bytes(vec![1])
        .expect("library")
        .with_data(data.clone());
    assert_eq!(lib.data().to_bytes(), data.as_bytes());
}
