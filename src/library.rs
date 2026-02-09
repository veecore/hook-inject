use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use crate::{
    Error, InjectedProcess, InjectedProgram, Process, Program, Result, inject_process,
    inject_program,
};

const DEFAULT_ENTRYPOINT: &str = "frida_agent_main";

#[derive(Clone, Debug)]
pub(crate) enum LibrarySource {
    Path(PathBuf),
    Blob(Vec<u8>),
}

/// Reference to an injectable library or in-memory payload.
#[derive(Clone, Debug)]
pub struct Library {
    source: LibrarySource,
    entrypoint: CString,
    data: CString,
}

impl Library {
    /// Create from an existing library path.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Library;
    /// let lib = Library::from_path("/path/to/libagent.so")?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Library> {
        let path = path.as_ref().to_path_buf();
        let meta = std::fs::metadata(&path).map_err(Error::from)?;
        if !meta.is_file() {
            return Err(Error::invalid_input("library path must be a file"));
        }

        library_with_defaults(LibrarySource::Path(path))
    }

    /// Create from raw in-memory bytes.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Library;
    /// let lib = Library::from_bytes(vec![1, 2, 3])?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn from_bytes<B: Into<Vec<u8>>>(bytes: B) -> Result<Library> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::invalid_input("library blob is empty"));
        }

        library_with_defaults(LibrarySource::Blob(bytes))
    }

    /// Resolve a cdylib built from a Rust crate.
    ///
    /// The path may be a directory containing Cargo.toml or a direct path to Cargo.toml.
    /// If the library is not found, this will run `cargo build` once and retry.
    ///
    /// You can optionally specify metadata in `Cargo.toml`:
    /// ```text
    /// [package.metadata.hook-inject]
    /// entrypoint = "my_entry"
    /// data = "hello"
    /// ```
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Library;
    /// let lib = Library::from_crate("./agent-crate")?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn from_crate<P: AsRef<Path>>(path: P) -> Result<Library> {
        let crate_path = path.as_ref();

        let dylib = if let Some(result) = hook_inject_build::read_cdylib_file(crate_path) {
            result.map_err(|err| {
                Error::invalid_input(format_args!("Failed to read library: {}", err))
            })?
        } else {
            hook_inject_build::build_cdylib(&crate_path).map_err(|err| {
                Error::invalid_input(format_args!("Failed to build library: {err}"))
            })?
        };

        Ok(Library {
            source: LibrarySource::Path(dylib.path),
            entrypoint: cstring_from_str(
                dylib.entrypoint.as_deref().unwrap_or(DEFAULT_ENTRYPOINT),
                "entrypoint",
            )?,
            data: cstring_from_str(dylib.data.as_deref().unwrap_or_default(), "data")?,
        })
    }

    /// Return the entrypoint symbol name.
    pub fn entrypoint(&self) -> &CStr {
        &self.entrypoint
    }

    /// Return the opaque data string passed to the entrypoint.
    pub fn data(&self) -> &CStr {
        &self.data
    }

    /// Override entrypoint function name.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Library;
    /// use std::ffi::CString;
    /// let lib = Library::from_path("/path/to/libagent.so")?
    ///     .with_entrypoint(CString::new("my_entry").unwrap());
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn with_entrypoint(mut self, entrypoint: impl Into<CString>) -> Self {
        self.entrypoint = entrypoint.into();
        self
    }

    /// Override data passed to the entrypoint.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Library;
    /// use std::ffi::CString;
    /// let lib = Library::from_path("/path/to/libagent.so")?
    ///     .with_data(CString::new("hello").unwrap());
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn with_data(mut self, data: impl Into<CString>) -> Self {
        self.data = data.into();
        self
    }

    /// Convenience helper to inject into a program at launch.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::{Library, Program};
    /// let lib = Library::from_path("/path/to/libagent.so")?;
    /// let program = Program::new("/usr/bin/true");
    /// let _ = lib.inject_program(program)?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn inject_program(self, program: impl Into<Program>) -> Result<InjectedProgram> {
        inject_program(program, self)
    }

    /// Convenience helper to inject into an existing process.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::{Library, Process};
    /// let lib = Library::from_path("/path/to/libagent.so")?;
    /// let process = unsafe { Process::from_pid_unchecked(1234) };
    /// let _ = lib.inject_into_process(process)?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn inject_into_process(self, process: Process) -> Result<InjectedProcess> {
        inject_process(process, self)
    }
}

impl Library {
    pub(crate) fn source(&self) -> &LibrarySource {
        &self.source
    }
}

fn cstring_from_str(value: &str, label: &'static str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::invalid_input(format!("{label} contains NUL")))
}

fn library_with_defaults(source: LibrarySource) -> Result<Library> {
    Ok(Library {
        source,
        entrypoint: cstring_from_str(DEFAULT_ENTRYPOINT, "entrypoint")?,
        data: cstring_from_str("", "data")?,
    })
}
