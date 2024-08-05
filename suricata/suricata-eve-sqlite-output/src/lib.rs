// Copyright (C) 2024  ANSSI
// SPDX-License-Identifier: GPL-2.0-or-later

// FFI helpers from https://github.com/jasonish/suricata-redis-output/blob/04f7b452afd55fa56f6900dad38eee42f482eee9/src/ffi.rs
// Maybe one day these will be included inside suricata crate.
mod ffi;

mod database;

use std::fmt::Debug;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc;

// Default configuration values.
const DEFAULT_DATABASE_URI: &str = "file:suricata/output/eve.db";
const DEFAULT_BUFFER_SIZE: &str = "1000";

#[derive(Debug, Clone)]
struct Config {
    filename: String,
    buffer: usize,
}

impl Config {
    fn new() -> Self {
        Self {
            filename: std::env::var("EVE_FILENAME").unwrap_or(DEFAULT_DATABASE_URI.into()),
            buffer: std::env::var("EVE_BUFFER")
                .unwrap_or(DEFAULT_BUFFER_SIZE.into())
                .parse()
                .expect("EVE_BUFFER is not an integer"),
        }
    }
}

struct Context {
    tx: mpsc::SyncSender<String>,
    count: usize,
}

fn output_init_rs(threaded: bool) -> Context {
    assert!(
        !threaded,
        "SQLite output plugin does not support threaded EVE yet"
    );

    // Load configuration
    let config = Config::new();

    let (tx, rx) = mpsc::sync_channel(config.buffer);
    let mut database_client = match database::Database::new(config.filename, rx) {
        Ok(client) => client,
        Err(err) => {
            log::error!("Failed to initialize Database client: {:?}", err);
            panic!()
        }
    };
    std::thread::spawn(move || database_client.run());
    Context { tx, count: 0 }
}

unsafe extern "C" fn output_init(
    _conf: *const c_void,
    threaded: bool,
    init_data: *mut *mut c_void,
) -> c_int {
    let context = output_init_rs(threaded);
    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    log::info!("SQLite output finished: count={}", context.count);
    std::mem::drop(context);
}

fn output_write_rs(buf: &str, context: &mut Context) {
    context.count += 1;

    if let Err(err) = context.tx.send(buf.to_string()) {
        log::error!("Eve record lost, {err:?}");
    }
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    _thread_data: *const c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);
    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len).to_str() {
        buf
    } else {
        return -1;
    };
    output_write_rs(buf, context);
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
    // Init Rust logger
    // We don't log using `suricata` crate to simplify this plugin and reduce build time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Register new eve filetype, then we can use it with `outputs.1.eve-log.filetype=sqlite`
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
    ffi::SCPlugin::new("Eve SQLite Output", "GPL-2.0", "ANSSI", init_plugin)
}
