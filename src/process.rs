use crate::{Error, Result};

/// Handle to a target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Process {
    pid: i32,
}

impl Process {
    /// # Safety
    /// The caller must ensure the PID is valid and refers to a live process.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Process;
    /// let process = unsafe { Process::from_pid_unchecked(1234) };
    /// ```
    pub unsafe fn from_pid_unchecked(pid: i32) -> Process {
        Process { pid }
    }

    /// Create a process handle after verifying the PID exists.
    ///
    /// On some platforms this probe may fail with a permission error instead
    /// of returning a definitive answer; in that case we surface the error to
    /// avoid false positives.
    ///
    /// # Examples
    /// ```no_run
    /// # use hook_inject::Process;
    /// let process = Process::from_pid(1234)?;
    /// # Ok::<(), hook_inject::Error>(())
    /// ```
    pub fn from_pid(pid: i32) -> Result<Process> {
        if pid <= 0 {
            return Err(Error::invalid_input("pid must be > 0"));
        }

        if process_exists(pid)? {
            Ok(Process { pid })
        } else {
            Err(Error::process_not_found(pid))
        }
    }

    /// Return the PID.
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

impl TryFrom<i32> for Process {
    type Error = Error;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        Process::from_pid(value)
    }
}

#[cfg(unix)]
fn process_exists(pid: i32) -> Result<bool> {
    use libc::kill;

    // POSIX: signal 0 performs permission/existence checks without delivering a signal.
    let res = unsafe { kill(pid, 0) };
    if res == 0 {
        return Ok(true);
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Err(Error::permission_denied(
            "permission denied while probing process (kill(pid, 0))",
        )),
        _ => Err(Error::from(err)),
    }
}

#[cfg(windows)]
fn process_exists(pid: i32) -> Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    if pid < 0 {
        return Ok(false);
    }

    let handle: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32) };
    if !handle.is_null() {
        unsafe { CloseHandle(handle) };
        return Ok(true);
    }

    let err = unsafe { GetLastError() };
    if err == ERROR_ACCESS_DENIED {
        // Access denied indicates the process likely exists; surface permission
        // failure to avoid a false-positive "exists" result.
        return Err(Error::permission_denied(
            "permission denied while probing process (OpenProcess)",
        ));
    }

    Ok(false)
}
