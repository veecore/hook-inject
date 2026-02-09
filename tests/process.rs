use hook_inject::Process;

#[test]
fn from_pid_rejects_nonpositive() {
    let err = Process::from_pid(0).unwrap_err();
    assert!(err.to_string().contains("pid must be > 0"));
}
