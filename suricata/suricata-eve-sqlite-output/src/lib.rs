// Copyright (C) 2024  ANSSI
// SPDX-License-Identifier: GPL-2.0-or-later

// FFI helpers from https://github.com/jasonish/suricata-redis-output/blob/04f7b452afd55fa56f6900dad38eee42f482eee9/src/ffi.rs
// Maybe one day these will be included inside suricata crate.
mod ffi;

mod database;

use rusqlite::Connection;
use std::fmt::Debug;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::Mutex;
use suricata::conf::ConfNode;
use suricata::{SCLogError, SCLogNotice};

// Default configuration values.
const DEFAULT_DATABASE_URI: &str = "file:eve.db";

#[derive(Debug, Clone)]
struct Config {
    filename: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            filename: DEFAULT_DATABASE_URI.into(),
        }
    }
}

impl Config {
    fn new(conf: &ConfNode) -> Self {
        let filename = conf
            .get_child_value("filename")
            .unwrap_or(DEFAULT_DATABASE_URI);
        Self {
            filename: filename.into(),
        }
    }
}

struct Context {
    conn: Mutex<Connection>,
    count: usize,
    dropped: usize,
}

unsafe extern "C" fn output_init(
    conf: *const c_void,
    threaded: bool,
    init_data: *mut *mut c_void,
) -> c_int {
    if threaded {
        SCLogError!("SQLite output plugin does not support threaded EVE yet");
        panic!()
    }

    // Load configuration
    let config = if conf.is_null() {
        Config::default()
    } else {
        Config::new(&ConfNode::wrap(conf))
    };

    // Open SQLite database and apply schema
    let conn = match Connection::open(config.filename) {
        Ok(c) => c,
        Err(err) => {
            SCLogError!("Failed to initialize SQLite connection: {err:?}");
            panic!()
        }
    };

    // WAL journal mode allows multiple concurrent readers
    conn.pragma_update(None, "journal_mode", "wal")
        .expect("Failed to set journal_mode=wal");
    conn.pragma_update(None, "synchronous", "off")
        .expect("Failed to set synchronous=off");

    // Init database schema
    conn.execute_batch(include_str!("schema.sql"))
        .expect("Failed to initialize database schema");

    let context = Context {
        conn: Mutex::new(conn),
        count: 0,
        dropped: 0,
    };

    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    SCLogNotice!(
        "SQLite output finished: count={}, dropped={}",
        context.count,
        context.dropped
    );
    std::mem::drop(context);
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    _thread_data: *const c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);

    // Convert the C string to a Rust string.
    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    context.count += 1;

    let conn = context.conn.lock().unwrap();
    if let Err(msg) = database::write_event(conn, buf) {
        SCLogError!("Failed to write event to database: {msg:?}");
        context.dropped += 1;
    }

    0
}

unsafe extern "C" fn output_thread_init(
    _init_data: *const c_void,
    _thread_id: std::os::raw::c_int,
    _thread_data: *mut *mut c_void,
) -> c_int {
    0
}

unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, _thread_data: *mut c_void) {}

unsafe extern "C" fn init_plugin() {
    let file_type = ffi::SCEveFileType::new(
        "sqlite",
        output_init,
        output_close,
        output_write,
        output_thread_init,
        output_thread_deinit,
    );
    ffi::SCRegisterEveFileType(file_type);
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Rust plugins need to initialize some Suricata internals so stuff like logging works.
    suricata::plugin::init();

    // Register our plugin.
    ffi::SCPlugin::new("Eve SQLite Output", "GPL-2.0", "ANSSI", init_plugin)
}
