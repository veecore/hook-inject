use std::fmt;
use std::fmt::Display;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    InvalidInput,
    NotSupported,
    RuntimeUnavailable,
    ProcessNotFound,
    PermissionDenied,
    Io,
    Runtime,
}

/// Error type for this crate.
///
/// This is intentionally a struct to minimize breaking changes over time, and
/// only exposes its message via `Display`.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub(crate) fn invalid_input(msg: impl Display) -> Self {
        Self::new(ErrorKind::InvalidInput, msg)
    }

    pub(crate) fn not_supported(msg: impl Display) -> Self {
        Self::new(ErrorKind::NotSupported, msg)
    }

    pub(crate) fn runtime_unavailable(msg: impl Display) -> Self {
        Self::new(ErrorKind::RuntimeUnavailable, msg)
    }

    pub(crate) fn process_not_found(pid: i32) -> Self {
        Self::new(
            ErrorKind::ProcessNotFound,
            format_args!("process not found: {pid}"),
        )
    }

    pub(crate) fn permission_denied(msg: impl Display) -> Self {
        Self::new(ErrorKind::PermissionDenied, msg)
    }

    pub(crate) fn runtime(msg: impl Display) -> Self {
        Self::new(ErrorKind::Runtime, msg)
    }

    pub(crate) fn from_io(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }

    fn new(kind: ErrorKind, msg: impl Display) -> Self {
        Self {
            kind,
            message: msg.to_string(),
            source: None,
        }
    }

    /// Returns true if the target process was not found.
    pub fn is_process_not_found(&self) -> bool {
        self.kind == ErrorKind::ProcessNotFound
    }

    /// Returns true if the error was caused by insufficient permissions.
    pub fn is_permission_denied(&self) -> bool {
        self.kind == ErrorKind::PermissionDenied
    }

    /// Returns true if the runtime injector is not available.
    pub fn is_runtime_unavailable(&self) -> bool {
        self.kind == ErrorKind::RuntimeUnavailable
    }

    /// Returns true if the runtime reported an error without a specific category.
    pub fn is_runtime_error(&self) -> bool {
        self.kind == ErrorKind::Runtime
    }

    /// Returns true if this operation is not supported on the current platform.
    pub fn is_not_supported(&self) -> bool {
        self.kind == ErrorKind::NotSupported
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            message: self.message.clone(),
            source: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::from_io(err)
    }
}
