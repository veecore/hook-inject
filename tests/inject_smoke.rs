#[test]
fn inject_fixture_into_target() {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use hook_inject::{Library, Process, inject_process};

    if !unix_socket_available() {
        eprintln!("skipping inject smoke test (unix socket bind denied)");
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_bin = root
        .join("target")
        .join("debug")
        .join("hook-inject-fixture-target");
    let stamp = std::env::temp_dir().join(format!(
        "hook-inject-{}-{}.stamp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));

    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("hook-inject-fixture-target")
        .current_dir(&root)
        .status()
        .expect("failed to build fixture target");
    assert!(status.success());

    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("hook-inject-fixture-agent")
        .current_dir(&root)
        .status()
        .expect("failed to build fixture agent");
    assert!(status.success());

    let mut child = Command::new(&target_bin)
        .arg("10000")
        .spawn()
        .expect("failed to spawn fixture target");

    let process = Process::from_pid(child.id() as i32).expect("target pid should exist");
    let library = Library::from_crate(root.join("fixtures/agent"))
        .expect("fixture lib")
        .with_data(std::ffi::CString::new(stamp.to_string_lossy().as_ref()).unwrap());

    let _inject = inject_process(process, library).expect("injection should succeed");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if stamp.is_file() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(stamp.is_file(), "expected injection to write stamp file");
    let contents = std::fs::read(&stamp).expect("read stamp");
    assert_eq!(contents, b"ok");

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn unix_socket_available() -> bool {
    use std::os::unix::net::UnixListener;

    let path = std::env::temp_dir().join(format!("hook-inject-sock-{}", std::process::id()));

    match UnixListener::bind(&path) {
        Ok(listener) => {
            drop(listener);
            let _ = std::fs::remove_file(path);
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn unix_socket_available() -> bool {
    true
}
