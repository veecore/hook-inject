//! Cross-platform process injection API.
//!
//! This crate provides a minimal, ergonomic API and delegates platform-specific
//! injection to a runtime engine (frida-core via FFI by default).
//!
//! # Quickstart
//! ```no_run
//! use hook_inject::{inject_process, Library, Process};
//!
//! let process = Process::from_pid(1234)?;
//! let library = Library::from_path("/path/to/libagent.so")?;
//! let injected = inject_process(process, library)?;
//! injected.uninject()?;
//! # Ok::<(), hook_inject::Error>(())
//! ```
//!
//! # Launching with `Program`
//! ```no_run
//! use hook_inject::{inject_program, Library, Program, Stdio};
//! use std::process::Command;
//!
//! let mut program = Program::new("/usr/bin/true");
//! program.arg("--version");
//! let program = program.stdio(Stdio::Null);
//! let mut cmd = Command::new("/usr/bin/true");
//! cmd.arg("--version");
//! let from_command: Program = cmd.into();
//! let library = Library::from_path("/path/to/libagent.so")?;
//! let _ = inject_program(program, library)?;
//! # let _ = from_command;
//! # Ok::<(), hook_inject::Error>(())
//! ```
//!
//! # Building agent libraries
//! If your agent is a Rust `cdylib`, you can point at its crate:
//! ```no_run
//! use hook_inject::Library;
//!
//! let agent = Library::from_crate("path/to/agent-crate")?;
//! # Ok::<(), hook_inject::Error>(())
//! ```
//!

mod backend;
mod error;
mod library;
mod process;
mod program;

pub use error::{Error, Result};
pub use library::Library;
pub use process::Process;
pub use program::{Child, Program, Stdio};

/// Inject a library into a program launched under injector control.
///
/// This spawns the process suspended, injects the library, and then resumes it.
/// Stdout/stderr pipes are not exposed on this path; if you need to capture
/// output, spawn with `Program::into_command()` and then inject by pid.
///
/// # Examples
/// ```no_run
/// use hook_inject::{inject_program, Library, Program, Stdio};
///
/// let mut program = Program::new("/usr/bin/true");
/// program.arg("--version");
/// let program = program.stdio(Stdio::Null);
/// let library = Library::from_path("/path/to/libagent.so")?;
/// let injected = inject_program(program, library)?;
/// injected.uninject()?;
/// # Ok::<(), hook_inject::Error>(())
/// ```
pub fn inject_program(
    spec: impl Into<Program>,
    library: impl Into<Library>,
) -> Result<InjectedProgram> {
    backend::default_backend()?.inject_program(spec.into(), library.into())
}

/// Inject a library into an already-running process.
///
/// # Examples
/// ```no_run
/// use hook_inject::{inject_process, Library, Process};
///
/// let process = unsafe { Process::from_pid_unchecked(1234) };
/// let library = Library::from_path("/path/to/libagent.so")?;
/// let injected = inject_process(process, library)?;
/// injected.uninject()?;
/// # Ok::<(), hook_inject::Error>(())
/// ```
pub fn inject_process(process: Process, library: impl Into<Library>) -> Result<InjectedProcess> {
    backend::default_backend()?.inject_process(process, library.into())
}

/// Spawn a program in a suspended state.
///
/// This is useful if you want to inject before the program starts executing.
///
/// # Examples
/// ```no_run
/// use hook_inject::{spawn, Program};
///
/// let suspended = spawn(Program::new("/usr/bin/true"))?;
/// let _child = suspended.resume()?;
/// # Ok::<(), hook_inject::Error>(())
/// ```
pub fn spawn(spec: impl Into<Program>) -> Result<SuspendedProgram> {
    backend::default_backend()?.spawn(spec.into())
}

/// Handle to a suspended program spawned by the injector.
#[derive(Debug)]
pub struct SuspendedProgram {
    backend: backend::BackendHandle,
    process: Process,
    stdio: Stdio,
}

impl SuspendedProgram {
    pub(crate) fn new(backend: backend::BackendHandle, process: Process, stdio: Stdio) -> Self {
        Self {
            backend,
            process,
            stdio,
        }
    }

    /// Return the target process handle.
    pub fn process(&self) -> Process {
        self.process
    }

    /// Inject a library and resume the suspended program.
    pub fn inject(self, library: Library) -> Result<InjectedProgram> {
        let injected = self.backend.inject_process(self.process, library)?;
        if let Err(err) = self.backend.resume(self.process) {
            let _ = injected.uninject();
            return Err(err);
        }

        let child = Child::new(self.process, self.stdio);
        Ok(injected.into_program(child))
    }

    /// Resume the suspended program without injection.
    ///
    /// Returns an opaque handle to the spawned program.
    pub fn resume(self) -> Result<Child> {
        self.backend.resume(self.process)?;
        Ok(Child::new(self.process, self.stdio))
    }
}

/// Handle to an injected library in a running process.
#[derive(Debug)]
pub struct InjectedProcess {
    backend: backend::BackendHandle,
    id: u64,
    process: Process,
}

impl InjectedProcess {
    pub(crate) fn new(backend: backend::BackendHandle, id: u64, process: Process) -> Self {
        Self {
            backend,
            id,
            process,
        }
    }

    /// Return the target process handle.
    pub fn process(&self) -> Process {
        self.process
    }

    /// Stop monitoring the injected library (Frida: `demonitor`).
    pub fn uninject(self) -> Result<()> {
        self.backend.uninject(self.id)
    }

    pub(crate) fn into_program(self, child: Child) -> InjectedProgram {
        InjectedProgram::new(self.backend, self.id, self.process, child)
    }
}

/// Handle to an injected library in a launched process.
#[derive(Debug)]
pub struct InjectedProgram {
    backend: backend::BackendHandle,
    id: u64,
    process: Process,
    child: Child,
}

impl InjectedProgram {
    pub(crate) fn new(
        backend: backend::BackendHandle,
        id: u64,
        process: Process,
        child: Child,
    ) -> Self {
        Self {
            backend,
            id,
            process,
            child,
        }
    }

    /// Return the target process handle.
    pub fn process(&self) -> Process {
        self.process
    }

    /// Access the opaque spawned-process handle.
    pub fn child(&self) -> &Child {
        &self.child
    }

    /// Stop monitoring the injected library (Frida: `demonitor`).
    pub fn uninject(self) -> Result<()> {
        self.backend.uninject(self.id)
    }
}
