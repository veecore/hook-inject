use hook_inject::Library;

fn main() {
    let library =
        Library::from_crate("/Users/tundeoladipupo/RustProjects/hook-inject/fixtures/agent")
            .unwrap();
    library
        .inject_program("/Users/tundeoladipupo/RustProjects/hook-inject/main")
        .unwrap();
}
