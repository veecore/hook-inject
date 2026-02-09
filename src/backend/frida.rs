use std::ffi::{CStr, CString, OsStr};
use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::library::LibrarySource;
use crate::{Error, Library, Process, Program, Result, Stdio};

#[repr(C)]
struct HookFridaCtx {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn hook_frida_new(error_kind_out: *mut c_int, error_out: *mut *mut c_char)
    -> *mut HookFridaCtx;
    fn hook_frida_free(ctx: *mut HookFridaCtx);

    fn hook_frida_inject_process(
        ctx: *mut HookFridaCtx,
        pid: i32,
        library_path: *const c_char,
        entrypoint: *const c_char,
        data: *const c_char,
        out_id: *mut u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn hook_frida_inject_blob(
        ctx: *mut HookFridaCtx,
        pid: i32,
        blob: *const u8,
        blob_len: usize,
        entrypoint: *const c_char,
        data: *const c_char,
        out_id: *mut u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn hook_frida_inject_launch(
        ctx: *mut HookFridaCtx,
        program: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
        cwd: *const c_char,
        stdio: i32,
        library_path: *const c_char,
        entrypoint: *const c_char,
        data: *const c_char,
        out_pid: *mut u32,
        out_id: *mut u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn hook_frida_spawn(
        ctx: *mut HookFridaCtx,
        program: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
        cwd: *const c_char,
        stdio: i32,
        out_pid: *mut u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn hook_frida_resume(
        ctx: *mut HookFridaCtx,
        pid: u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn hook_frida_demonitor(
        ctx: *mut HookFridaCtx,
        id: u32,
        error_kind_out: *mut c_int,
        error_out: *mut *mut c_char,
    ) -> c_int;
    fn hook_frida_string_free(s: *mut c_char);
}

pub(crate) fn init() -> Result<FridaBackend> {
    unsafe {
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let ctx = hook_frida_new(
            &mut err_kind as *mut c_int,
            &mut err_ptr as *mut *mut c_char,
        );
        if ctx.is_null() {
            let msg = read_error(err_ptr);
            return Err(Error::runtime_unavailable(msg));
        }

        Ok(FridaBackend { ctx })
    }
}

pub(super) struct FridaBackend {
    ctx: *mut HookFridaCtx,
}

// Frida's injector context is used only through its C API, which is designed
// for concurrent use; we treat the opaque pointer as Send/Sync here.
unsafe impl Send for FridaBackend {}
unsafe impl Sync for FridaBackend {}

impl Drop for FridaBackend {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                hook_frida_free(self.ctx);
                self.ctx = ptr::null_mut();
            }
        }
    }
}

impl FridaBackend {
    pub(super) fn inject_launch(
        &self,
        spec: &mut Program,
        library: &Library,
    ) -> Result<(Process, u64)> {
        match library.source() {
            LibrarySource::Path(_) => self.inject_launch_path(spec, library),
            LibrarySource::Blob(_) => {
                let process = self.spawn(spec)?;
                let id = self.inject_blob(process, library)?;
                self.resume(process)?;
                Ok((process, id))
            }
        }
    }

    pub(super) fn inject_process(&self, process: Process, library: &Library) -> Result<u64> {
        match library.source() {
            LibrarySource::Path(_) => self.inject_process_path(process, library),
            LibrarySource::Blob(_) => self.inject_blob(process, library),
        }
    }

    fn inject_launch_path(&self, spec: &mut Program, library: &Library) -> Result<(Process, u64)> {
        let program_path = spec.command().get_program();
        let program = os_str_to_cstring(program_path, "program")?;
        let library_path = match library.source() {
            LibrarySource::Path(path) => os_str_to_cstring(path, "library_path")?,
            LibrarySource::Blob(_) => {
                return Err(Error::invalid_input(
                    "library must be a file path for launch",
                ));
            }
        };
        let entrypoint = library.entrypoint();
        let data = library.data();

        let argv_storage = build_argv(spec, &program)?;
        let envp_storage = build_envp(spec)?;
        let cwd = spec
            .command()
            .get_current_dir()
            .map(|dir| os_str_to_cstring(dir, "cwd"))
            .transpose()?;

        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let mut pid_out: u32 = 0;
        let mut id_out: u32 = 0;

        let ok = unsafe {
            hook_frida_inject_launch(
                self.ctx,
                program.as_ptr(),
                argv_storage.ptrs.as_ptr(),
                envp_storage.ptrs.as_ptr(),
                cwd.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                map_stdio(spec.stdio_value()),
                library_path.as_ptr(),
                entrypoint.as_ptr(),
                data.as_ptr(),
                &mut pid_out as *mut u32,
                &mut id_out as *mut u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };

        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, None));
        }

        let process = unsafe { Process::from_pid_unchecked(pid_out as i32) };
        Ok((process, id_out as u64))
    }

    fn inject_process_path(&self, process: Process, library: &Library) -> Result<u64> {
        let library_path = match library.source() {
            LibrarySource::Path(path) => os_str_to_cstring(path, "library_path")?,
            LibrarySource::Blob(_) => {
                return Err(Error::invalid_input("library must be a file path"));
            }
        };
        let entrypoint = library.entrypoint();
        let data = library.data();

        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let mut id_out: u32 = 0;

        let ok = unsafe {
            hook_frida_inject_process(
                self.ctx,
                process.pid(),
                library_path.as_ptr(),
                entrypoint.as_ptr(),
                data.as_ptr(),
                &mut id_out as *mut u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };

        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, None));
        }

        Ok(id_out as u64)
    }

    fn inject_blob(&self, process: Process, library: &Library) -> Result<u64> {
        let bytes = match library.source() {
            LibrarySource::Blob(bytes) => bytes,
            LibrarySource::Path(_) => {
                return Err(Error::invalid_input("library is not a blob"));
            }
        };
        let entrypoint = library.entrypoint();
        let data = library.data();

        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let mut id_out: u32 = 0;

        let ok = unsafe {
            hook_frida_inject_blob(
                self.ctx,
                process.pid(),
                bytes.as_ptr(),
                bytes.len(),
                entrypoint.as_ptr(),
                data.as_ptr(),
                &mut id_out as *mut u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };

        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, None));
        }

        Ok(id_out as u64)
    }

    pub(super) fn spawn(&self, spec: &mut Program) -> Result<Process> {
        let program_path = spec.command().get_program();
        let program = os_str_to_cstring(program_path, "program path")?;

        let argv_storage = build_argv(spec, &program)?;
        let envp_storage = build_envp(spec)?;
        let cwd = spec
            .command()
            .get_current_dir()
            .map(|dir| {
                CString::new(dir.to_string_lossy().as_bytes())
                    .map_err(|_| Error::invalid_input("cwd contains NUL"))
            })
            .transpose()?;

        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let mut pid_out: u32 = 0;

        let ok = unsafe {
            hook_frida_spawn(
                self.ctx,
                program.as_ptr(),
                argv_storage.ptrs.as_ptr(),
                envp_storage.ptrs.as_ptr(),
                cwd.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                map_stdio(spec.stdio_value()),
                &mut pid_out as *mut u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };

        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, None));
        }

        let process = unsafe { Process::from_pid_unchecked(pid_out as i32) };
        Ok(process)
    }

    pub(super) fn resume(&self, process: Process) -> Result<()> {
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let ok = unsafe {
            hook_frida_resume(
                self.ctx,
                process.pid() as u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };
        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, Some(process.pid())));
        }
        Ok(())
    }

    pub(super) fn uninject(&self, id: u64) -> Result<()> {
        if id == 0 {
            return Ok(());
        }

        let mut err_ptr: *mut c_char = ptr::null_mut();
        let mut err_kind: c_int = HOOK_FRIDA_ERROR_NONE;
        let ok = unsafe {
            hook_frida_demonitor(
                self.ctx,
                id as u32,
                &mut err_kind as *mut c_int,
                &mut err_ptr as *mut *mut c_char,
            )
        };
        if ok <= 0 {
            return Err(new_frida_error(err_kind, err_ptr, None));
        }
        Ok(())
    }
}

struct CArgv {
    _cstrings: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

struct CEnvp {
    _cstrings: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

fn build_argv(spec: &Program, program: &CString) -> Result<CArgv> {
    // Frida expects a NULL-terminated argv array; keep owned CStrings alive.
    let mut cstrings = Vec::new();
    cstrings.push(program.clone());
    for arg in spec.command().get_args() {
        let s = CString::new(arg.to_string_lossy().as_bytes())
            .map_err(|_| Error::invalid_input("arg contains NUL"))?;
        cstrings.push(s);
    }

    let mut ptrs: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(ptr::null());

    Ok(CArgv {
        _cstrings: cstrings,
        ptrs,
    })
}

fn build_envp(spec: &Program) -> Result<CEnvp> {
    // Frida expects envp entries as KEY=VALUE strings, NULL-terminated.
    let mut cstrings = Vec::new();
    for (k, v) in spec.command().get_envs() {
        if let Some(v) = v {
            let mut kv = k.to_string_lossy().into_owned();
            kv.push('=');
            kv.push_str(&v.to_string_lossy());
            let s = CString::new(kv.as_bytes())
                .map_err(|_| Error::invalid_input("env contains NUL"))?;
            cstrings.push(s);
        }
    }

    if cstrings.is_empty() {
        return Ok(CEnvp {
            _cstrings: Vec::new(),
            ptrs: vec![ptr::null()],
        });
    }

    let mut ptrs: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(ptr::null());

    Ok(CEnvp {
        _cstrings: cstrings,
        ptrs,
    })
}

fn map_stdio(stdio: Stdio) -> i32 {
    match stdio {
        Stdio::Inherit => 0,
        Stdio::Null => 1,
        Stdio::Pipe => 2,
    }
}
fn new_frida_error(err_kind: c_int, err_ptr: *mut c_char, pid: Option<i32>) -> Error {
    let msg = read_error(err_ptr);
    map_frida_error(err_kind, msg, pid)
}

// Mirror the shim's error kind codes to preserve a stable Rust API.
const HOOK_FRIDA_ERROR_NONE: c_int = 0;
const HOOK_FRIDA_ERROR_INVALID_ARGUMENT: c_int = 1;
const HOOK_FRIDA_ERROR_NOT_SUPPORTED: c_int = 2;
const HOOK_FRIDA_ERROR_PERMISSION_DENIED: c_int = 3;
const HOOK_FRIDA_ERROR_PROCESS_NOT_FOUND: c_int = 4;
#[allow(dead_code)]
const HOOK_FRIDA_ERROR_RUNTIME: c_int = 5;

fn map_frida_error(kind: c_int, msg: String, pid: Option<i32>) -> Error {
    // Map Frida error kinds into the public Rust error surface.
    match kind {
        HOOK_FRIDA_ERROR_INVALID_ARGUMENT => Error::invalid_input(msg),
        HOOK_FRIDA_ERROR_NOT_SUPPORTED => Error::not_supported(msg),
        HOOK_FRIDA_ERROR_PERMISSION_DENIED => Error::permission_denied(msg),
        HOOK_FRIDA_ERROR_PROCESS_NOT_FOUND => {
            if let Some(pid) = pid {
                Error::process_not_found(pid)
            } else {
                Error::runtime(msg)
            }
        }
        _ => Error::runtime(msg),
    }
}

fn read_error(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return "unknown error".to_string();
    }

    unsafe {
        let msg = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        hook_frida_string_free(ptr);
        msg
    }
}

fn os_str_to_cstring(os_str: impl AsRef<OsStr>, var_name: &'static str) -> Result<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        CString::new(os_str.as_ref().as_bytes())
            .map_err(|err| Error::invalid_input(format_args!("{var_name}: {err}")))
    }

    #[cfg(not(unix))]
    {
        CString::new(os_str.as_ref().to_string_lossy().as_bytes())
            .map_err(|err| Error::invalid_input(format_args!("{var_name}: {err}")))
    }
}
