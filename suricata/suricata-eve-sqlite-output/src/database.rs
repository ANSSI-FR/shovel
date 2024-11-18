// Copyright (C) 2024  ANSSI
// SPDX-License-Identifier: GPL-2.0-or-later

use regex_lite::Regex;
use rusqlite::Transaction;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref RE_EVENT_TYPE: Regex = Regex::new(r#""event_type":"([^"]+)""#).unwrap();
    static ref RE_SRC_IP: Regex = Regex::new(r#""src_ip":"([^"]+)""#).unwrap();
    static ref RE_DEST_IP: Regex = Regex::new(r#""dest_ip":"([^"]+)""#).unwrap();
    static ref RE_APP_PROTO: Regex = Regex::new(r#""app_proto":"([^"]+)""#).unwrap();
    static ref RE_FLOW_ID: Regex = Regex::new(r#""flow_id":(\d+)"#).unwrap();
    static ref RE_PCAP_FILENAME: Regex = Regex::new(r#""pcap_filename":"([^"]+)""#).unwrap();
    static ref FLOW_PCAP: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
}

fn sc_ip_format(sc_ipaddr: String) -> String {
    match sc_ipaddr.parse().expect("invalid IP address") {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// Add one Eve event to the SQL database
fn write_event(transaction: &Transaction, buf: &str) -> Result<usize, rusqlite::Error> {
    // Use regex rather than JSON parsing for performance reasons.
    // Ignore events that don't have event_type field, such as stats.
    let Some(event_type_caps) = RE_EVENT_TYPE.captures(buf) else {
        return Ok(0);
    };
    let event_type = &event_type_caps[1];

    // HACK: collect pcap_filename from app events, then use it later when writing flow event.
    // `pcap_filename` pointed by flow events seem wrong, this is maybe a Suricata bug.
    if event_type != "flow" {
        let flow_id_str = &RE_FLOW_ID.captures(buf).expect("missing flow_id")[1];
        let flow_id: u64 = flow_id_str.parse().expect("flow_id is not a u64");
        let pcap_filename_cap = RE_PCAP_FILENAME.captures(buf);
        if let Some(pcap_filename) = pcap_filename_cap.as_ref().map(|c| &c[1]) {
            if let Ok(ref mut m) = FLOW_PCAP.try_lock() {
                m.insert(flow_id, pcap_filename.to_string());
            } else {
                log::warn!("Failed to lock FLOW_PCAP mutex, skipping insertion");
            }
        }
    }

    match event_type {
        "flow" => {
            let src_ip = &RE_SRC_IP.captures(buf).expect("missing src_ip")[1];
            let dest_ip = &RE_DEST_IP.captures(buf).expect("missing dest_ip")[1];
            let flow_id_str = &RE_FLOW_ID.captures(buf).expect("missing flow_id")[1];
            let flow_id: u64 = flow_id_str.parse().expect("flow_id is not a u64");
            let pcap_filename_cap = RE_PCAP_FILENAME.captures(buf);
            let flow_pcap_local = FLOW_PCAP.lock().unwrap();
            let pcap_filename = match flow_pcap_local.get(&flow_id) {
                Some(v) => v,
                None => pcap_filename_cap.as_ref().map(|c| &c[1]).unwrap_or(""),
            };
            transaction.execute(
                "INSERT OR IGNORE INTO flow (id, src_ip, src_port, dest_ip, dest_port, pcap_filename, proto, app_proto, metadata, extra_data) \
                values(?1->>'flow_id', ?2, ?1->>'src_port', ?3, ?1->>'dest_port', ?4, ?1->>'proto', ?1->>'app_proto', ?1->'metadata', ?1->'flow')",
                (buf, sc_ip_format(src_ip.to_string()), sc_ip_format(dest_ip.to_string()), pcap_filename),
            )
        },
        "alert" => {
            transaction.execute(
                "INSERT OR IGNORE INTO alert (flow_id, timestamp, extra_data) \
                values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), json_extract(?1, '$.' || ?2))",
                (buf, event_type),
            )
        },
        "anomaly" => {
            transaction.execute(
                "INSERT OR IGNORE INTO anomaly (flow_id, timestamp, extra_data) \
                values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), json_extract(?1, '$.' || ?2))",
                (buf, event_type),
            )
        },
        "fileinfo" => {
            transaction.execute(
                "INSERT OR IGNORE INTO fileinfo (flow_id, timestamp, extra_data) \
                values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), json_extract(?1, '$.' || ?2))",
                (buf, event_type),
            )
        },
        _ => {
            transaction.execute(
                "INSERT OR IGNORE INTO 'app-event' (flow_id, timestamp, app_proto, extra_data) \
                values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), ?2, json_extract(?1, '$.' || ?2))",
                (buf, event_type),
            )
        }
    }
}

pub struct Database {
    conn: rusqlite::Connection,
    rx: std::sync::mpsc::Receiver<String>,
    count: usize,
    count_inserted: usize,
}

impl Database {
    /// Open SQLite database connection in WAL journal mode then init schema
    pub fn new(
        filename: String,
        rx: std::sync::mpsc::Receiver<String>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(filename)?;
        conn.pragma_update(None, "journal_mode", "wal")
            .expect("Failed to set journal_mode=wal");
        conn.pragma_update(None, "synchronous", "off")
            .expect("Failed to set synchronous=off");
        conn.execute_batch(include_str!("schema.sql"))
            .expect("Failed to initialize database schema");
        Ok(Self {
            conn,
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    fn batch_write_events(&mut self) -> Result<(), rusqlite::Error> {
        while let Ok(buf) = self.rx.recv() {
            let transaction = self.conn.transaction()?;

            // Insert first event
            self.count += 1;
            self.count_inserted += write_event(&transaction, &buf)?;

            // Insert remaining events
            let batch = self
                .rx
                .try_iter()
                .map(|buf| write_event(&transaction, &buf))
                .collect::<Result<Vec<_>, _>>()?;
            self.count += batch.len();
            self.count_inserted += batch.iter().sum::<usize>();

            transaction.commit()?;
        }
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        if let Err(err) = self.batch_write_events() {
            log::error!("Failed to write batch of events: {err:?}");
        }
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
