use hook_inject::Library;

#[test]
fn blob_rejects_empty() {
    let err = Library::from_bytes(Vec::<u8>::new()).unwrap_err();
    assert!(err.to_string().contains("library blob is empty"));
}

#[test]
fn blob_accepts_bytes() {
    let lib = Library::from_bytes(vec![1, 2, 3]).unwrap();
    assert_eq!(lib.entrypoint().to_str().unwrap(), "frida_agent_main");
    assert_eq!(lib.data().to_str().unwrap(), "");
}
