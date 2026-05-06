use hook_inject::{Library, Process};

fn main() {
    let library =
        Library::from_crate("/Users/tundeoladipupo/RustProjects/hook-inject/fixtures/agent")
            .unwrap()
            .with_entrypoint(c"hook_inject_entry")
            .with_data(c"/tmp/new_file");
    // library
    //     .inject_program("/Users/tundeoladipupo/RustProjects/hook-inject/zz_lab/misc/mango")
    //     .unwrap();
    library
        .inject_into_process(unsafe { Process::from_pid_unchecked(3626) })
        .unwrap();
}
