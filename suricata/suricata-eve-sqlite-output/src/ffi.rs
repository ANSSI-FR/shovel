// Copyright (c) 2021 Open Information Security Foundation
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

/// Helper module for this plugin to provide better interfaces to the C API.
/// This will become part of the Suricata dependency crate at some point.
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// Rust representation of a C plugin.
#[repr(C)]
pub struct SCPlugin {
    name: *const c_char,
    license: *const c_char,
    author: *const c_char,
    init: unsafe extern "C" fn(),
}

impl SCPlugin {
    pub fn new(
        name: &str,
        license: &str,
        author: &str,
        init_fn: unsafe extern "C" fn(),
    ) -> *const Self {
        let name = CString::new(name).unwrap();
        let license = CString::new(license).unwrap();
        let author = CString::new(author).unwrap();
        let plugin = SCPlugin {
            name: name.into_raw(),
            license: license.into_raw(),
            author: author.into_raw(),
            init: init_fn,
        };
        Box::into_raw(Box::new(plugin))
    }
}

pub type InitFn =
    unsafe extern "C" fn(conf: *const c_void, threaded: bool, init_data: *mut *mut c_void) -> c_int;
pub type DeinitFn = unsafe extern "C" fn(init_data: *const c_void);
pub type WriteFn = unsafe extern "C" fn(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    thread_data: *const c_void,
) -> c_int;
pub type ThreadInitFn = unsafe extern "C" fn(
    init_data: *const c_void,
    thread_id: std::os::raw::c_int,
    thread_data: *mut *mut c_void,
) -> c_int;
pub type ThreadDeinitFn = unsafe extern "C" fn(init_data: *const c_void, thread_data: *mut c_void);

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCEveFileType {
    pub name: *const c_char,
    pub open: InitFn,
    pub write: WriteFn,
    pub close: DeinitFn,
    pub thread_init: ThreadInitFn,
    pub thread_deinit: ThreadDeinitFn,
    pad: [usize; 2],
}

impl SCEveFileType {
    pub fn new(
        name: &str,
        open: InitFn,
        close: DeinitFn,
        write: WriteFn,
        thread_init: ThreadInitFn,
        thread_deinit: ThreadDeinitFn,
    ) -> *const Self {
        // Convert the name to C and forget.
        let name = CString::new(name).unwrap().into_raw();
        let file_type = SCEveFileType {
            name,
            open,
            close,
            write,
            thread_init,
            thread_deinit,
            pad: [0, 0],
        };
        Box::into_raw(Box::new(file_type))
    }
}

extern "C" {
    pub fn SCRegisterEveFileType(filetype: *const SCEveFileType) -> bool;
}

// Convert a C string with a provided length to a Rust &str.
//
// This is an alternative to CStr::from_ptr when the length is already known to avoid the
// scan of the string to find the length (strlen).
pub fn str_from_c_parts<'a>(buffer: *const c_char, buffer_len: c_int) -> &'a CStr {
    unsafe {
        CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
            buffer as *const u8,
            buffer_len as usize + 1,
        ))
    }
}
