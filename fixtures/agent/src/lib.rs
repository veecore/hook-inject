use std::ffi::{CStr, c_char};
use std::fs;

#[unsafe(no_mangle)]
pub extern "C" fn hook_inject_entry(
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
