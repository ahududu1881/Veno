//! Örnek Veno Plugin — Rust
//! Derleme: rustc --crate-type=cdylib -O -o libexample.so example.rs

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

#[no_mangle] pub extern "C" fn veno_plugin_name()    -> *const c_char { CString::new("example_guard").unwrap().into_raw() }
#[no_mangle] pub extern "C" fn veno_plugin_version() -> *const c_char { CString::new("1.0.0").unwrap().into_raw() }
#[no_mangle] pub extern "C" fn veno_init()    -> c_int { 0 }
#[no_mangle] pub extern "C" fn veno_destroy() {}

#[no_mangle]
pub extern "C" fn veno_on_request(_method: *const c_char, path: *const c_char, headers: *const c_char) -> c_int {
    let path_str    = unsafe { CStr::from_ptr(path)    }.to_str().unwrap_or("");
    let headers_str = unsafe { CStr::from_ptr(headers) }.to_str().unwrap_or("");
    if path_str.starts_with("/admin") {
        if !headers_str.contains("127.0.0.1") && !headers_str.contains("::1") { return 1; }
    }
    0
}
#[no_mangle] pub extern "C" fn veno_on_response(_status: c_int, _ct: *const c_char) -> c_int { 0 }
