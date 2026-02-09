use hook_inject::{Library, Process, inject_process};

#[test]
fn stub_build_reports_runtime_unavailable() {
    if std::env::var_os("HOOK_INJECT_SKIP_FRIDA_BUILD").is_none() {
        eprintln!("skipping stub runtime test (real build)");
        return;
    }

    let process = unsafe { Process::from_pid_unchecked(1234) };
    let library = Library::from_bytes(vec![1]).expect("library");
    let err = inject_process(process, library).expect_err("stub should fail");
    assert!(err.is_runtime_unavailable());
}
