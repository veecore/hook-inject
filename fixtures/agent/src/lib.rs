use std::ffi::{CStr, c_char};
use std::fs;

/// # Safety
/// `data` must be a valid NUL-terminated C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hook_inject_entry(
    data: *const c_char,
    _stay_resident: *mut i32,
    _state: *mut core::ffi::c_void,
) {
    if data.is_null() {
        return;
    }

    let data = unsafe { CStr::from_ptr(data) };
    let path = data.to_string_lossy();
    if path.is_empty() {
        return;
    }

    let _ = fs::write(path.as_ref(), b"ok");
}
