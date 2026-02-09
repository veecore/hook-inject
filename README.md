# hook-inject

Cross-platform process injection API backed by Frida Core.

This crate provides a minimal Rust API for injecting a shared library into a
running process or a process launched under injector control. Internally it
builds and links against `frida-core` and calls into a tiny C shim. The injector
uses Frida's helper-based backend by default; set `HOOK_INJECT_INJECTOR=inprocess`
to avoid the helper process (at the cost of compatibility on some systems).
On certain errors (e.g. permission denied on macOS) it falls back to device-based
injection, which may spawn a helper process.

## Quickstart

```rust
use hook_inject::{inject_process, Library, Process};

let process = Process::from_pid(1234)?;
let library = Library::from_path("/path/to/libagent.so")?;
let injected = inject_process(process, library)?;

injected.uninject()?;
```

Launch + inject:

```rust
use hook_inject::{inject_program, Library, Program, Stdio};

let mut program = Program::new("/usr/bin/true");
program.arg("--version");
let program = program.stdio(Stdio::Null);

let library = Library::from_path("/path/to/libagent.so")?;
let injected = inject_program(program, library)?;

injected.uninject()?;
```

Spawn suspended (manual resume):

```rust
use hook_inject::{spawn, Program};

let suspended = spawn(Program::new("/usr/bin/true"))?;
let _child = suspended.resume()?;
```

Spawn + inject with output capture:

```rust
use hook_inject::{inject_process, Library, Process, Program, Stdio};
use std::io::Read;
use std::process::Command;

let program = Program::new("/usr/bin/true").stdio(Stdio::Pipe);
let library = Library::from_path("/path/to/libagent.so")?;
let mut cmd: Command = program.into_command();
let mut child = cmd.spawn()?;
let process = unsafe { Process::from_pid_unchecked(child.id() as i32) };
let _injected = inject_process(process, library)?;

let mut stdout = String::new();
if let Some(out) = child.stdout.as_mut() {
    out.read_to_string(&mut stdout)?;
}
```

Inject from an in-memory blob:

```rust
use hook_inject::{inject_process, Library, Process};

let process = unsafe { Process::from_pid_unchecked(1234) };
let blob = Library::from_bytes(vec![1, 2, 3])?;
let injected = inject_process(process, blob)?;
injected.uninject()?;
```

## Building agent libraries

### Existing library path

```rust
use hook_inject::Library;

let lib = Library::from_path("/path/to/libagent.so")?;
```

### Discover a Rust cdylib

```rust
use hook_inject::Library;

let lib = Library::from_crate("./agent-crate")?;
```

If the cdylib is missing, `from_crate` runs `cargo build` once and retries.

## Dependencies

This crate downloads a prebuilt Frida Core devkit (headers + shared library)
by default and links against it.

If you already have a prebuilt Frida Core devkit, you can skip the download by
setting:

```
export FRIDA_CORE_DEVKIT_DIR=/path/to/frida-core-devkit
```

If you prefer to build a devkit from source, run:

```
./scripts/build_frida_core_devkit.sh
export FRIDA_CORE_DEVKIT_DIR=vendor/frida-core/build-hook-inject/src/devkit
```

The build script downloads into `target/frida-devkit/<version>/<platform>` by
default. You can override its behavior with:

- `HOOK_INJECT_DEVKIT_VERSION` (default `17.6.2`)
- `HOOK_INJECT_DEVKIT_PLATFORM` (e.g., `linux-x86_64`, `macos-arm64`)

## macOS permissions

On macOS, Frida uses `task_for_pid()` under the hood. If your system denies
this call, you will see `PermissionDenied` errors when attaching or injecting.

You can verify access with the included helper:

```sh
clang scripts/task_for_pid_test.c \
  -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
  -o /tmp/task_for_pid_test

/tmp/task_for_pid_test <pid>
```

If the test fails, ensure your user is allowed to debug (Developer Tools
access) or run with elevated privileges.

You need the following tools and libraries installed:

- pkg-config
- glib-2.0
- json-glib
- libffi

If you build the devkit from source using `scripts/build_frida_core_devkit.sh`,
you also need:

- Meson + Ninja

The devkit download path uses `curl` + `tar` on Unix and PowerShell on Windows.

## Environment overrides

- `HOOK_INJECT_INJECTOR=inprocess` uses Frida's in-process injector instead of
  the default helper-based injector.

Common install commands:

- macOS (Homebrew): `brew install meson ninja pkg-config glib json-glib libffi`
- Ubuntu/Debian: `sudo apt-get install -y meson ninja-build pkg-config libglib2.0-dev libjson-glib-dev libffi-dev`

## Testing

### Full runtime build + tests

```bash
cargo test --workspace
```

### CI stub build (compiles without Frida deps)

```bash
HOOK_INJECT_SKIP_FRIDA_BUILD=1 cargo test --workspace
```

### Injection smoke test (Linux)

```bash
cargo test -p hook-inject --test inject_smoke -- --ignored
```

## Notes

- The runtime engine is Frida by default; there is no alternate selector.
- On some platforms, process probing can fail with permission errors. In that
  case `Process::from_pid` will return `Error::PermissionDenied` instead of
  falsely reporting the process exists.

## License

MIT OR Apache-2.0
