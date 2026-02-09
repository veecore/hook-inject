use std::ffi::OsStr;
use std::ops::{Deref, DerefMut};
use std::process::Command;

use crate::Process;

// Note: not every `Command` setting is honored by Frida's spawn API. We capture
// program, args, env, cwd, and stdio for injection purposes.
/// Wrapper around a program launch specification.
///
/// This is a type-safe, introspectable equivalent of `std::process::Command`.
/// When used with `inject_program`, stdio pipes are not exposed; spawn with
/// `std::process::Command` if you need to capture output.
///
/// # Examples
/// ```no_run
/// use hook_inject::Program;
///
/// let mut program = Program::new("/usr/bin/true");
/// program.arg("--version");
/// ```
///
/// Converting from `Command` captures program, args, env, and cwd; stdio defaults to `Inherit`
/// for Frida launches, so call `.stdio()` if you need `Null` or `Pipe` there.
#[derive(Debug)]
pub struct Program {
    cmd: Command,
    stdio: Stdio,
}

/// How to configure the child process stdio.
#[derive(Clone, Debug, Copy)]
pub enum Stdio {
    /// Inherit parent stdio handles.
    Inherit,
    /// Redirect stdio to `/dev/null` (or equivalent).
    Null,
    /// Create pipes for stdio (pipe handles are exposed by `Command::spawn`).
    Pipe,
}

impl Program {
    /// Create a new launch specification.
    pub fn new<P: AsRef<OsStr>>(program: P) -> Self {
        Self {
            cmd: Command::new(program),
            stdio: Stdio::Inherit,
        }
    }

    /// Set stdio mode for the launched process.
    pub fn stdio(mut self, stdio: Stdio) -> Self {
        use std::process::Stdio as StdStdio;

        match stdio {
            Stdio::Inherit => {
                self.cmd.stdin(StdStdio::inherit());
                self.cmd.stdout(StdStdio::inherit());
                self.cmd.stderr(StdStdio::inherit());
            }
            Stdio::Null => {
                self.cmd.stdin(StdStdio::null());
                self.cmd.stdout(StdStdio::null());
                self.cmd.stderr(StdStdio::null());
            }
            Stdio::Pipe => {
                self.cmd.stdin(StdStdio::piped());
                self.cmd.stdout(StdStdio::piped());
                self.cmd.stderr(StdStdio::piped());
            }
        }

        self.stdio = stdio;
        self
    }

    pub(crate) fn stdio_value(&self) -> Stdio {
        self.stdio
    }

    pub(crate) fn command(&self) -> &Command {
        &self.cmd
    }

    /// Convert this launch spec into a standard `Command`.
    pub fn into_command(self) -> Command {
        self.cmd
    }
}

impl From<Command> for Program {
    fn from(cmd: Command) -> Self {
        Program {
            cmd,
            stdio: Stdio::Inherit,
        }
    }
}

impl From<&OsStr> for Program {
    fn from(program: &OsStr) -> Self {
        Program::new(program)
    }
}

impl From<&str> for Program {
    fn from(program: &str) -> Self {
        Program::new(program)
    }
}

impl From<Program> for Command {
    fn from(program: Program) -> Self {
        program.cmd
    }
}

impl Deref for Program {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.cmd
    }
}

impl DerefMut for Program {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cmd
    }
}

/// Opaque handle to a launched process spawned by the injector.
///
/// This exists for API stability; it intentionally exposes no child-style
/// methods until Frida exposes the necessary handles.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Child {
    pid: i32,
    stdio: Stdio,
    _priv: (),
}

impl Child {
    pub(crate) fn new(process: Process, stdio: Stdio) -> Self {
        Self {
            pid: process.pid(),
            stdio,
            _priv: (),
        }
    }
}
