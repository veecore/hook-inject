#[test]
fn spawn_resume_smoke() {
    use hook_inject::{Program, spawn};

    if !cfg!(target_os = "linux") {
        eprintln!("skipping spawn smoke test (non-linux)");
        return;
    }

    let program = Program::new("/usr/bin/true");
    let suspended = spawn(program).expect("spawn suspended");
    let _child = suspended.resume().expect("resume");
}
