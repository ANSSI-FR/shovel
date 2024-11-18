-- Copyright (C) 2024  ANSSI
-- SPDX-License-Identifier: GPL-2.0-or-later
CREATE TABLE IF NOT EXISTS "flow" (
    id INTEGER NOT NULL PRIMARY KEY,
    -- SQLite UNIXEPOCH currently has only millisecond precision using "subsec", which is not enough
    ts_start INTEGER GENERATED ALWAYS
        AS (UNIXEPOCH(SUBSTR(extra_data->>'start', 1, 19))*1000000 + SUBSTR(extra_data->>'start', 21, 6)) STORED,
    ts_end INTEGER GENERATED ALWAYS
        AS (UNIXEPOCH(SUBSTR(extra_data->>'end', 1, 19))*1000000 + SUBSTR(extra_data->>'end', 21, 6)) STORED,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    src_ipport TEXT GENERATED ALWAYS
        AS (src_ip || IIF(src_port IS NULL, '', ':' || src_port)),
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    dest_ipport TEXT GENERATED ALWAYS
        AS (dest_ip || IIF(dest_port IS NULL, '', ':' || dest_port)),
    pcap_filename TEXT,
    proto TEXT NOT NULL,
    app_proto TEXT,
    metadata TEXT,
    extra_data TEXT
);
CREATE TABLE IF NOT EXISTS "alert" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    tag TEXT GENERATED ALWAYS
        AS (extra_data->>'$.metadata.tag[0]') STORED,
    color TEXT GENERATED ALWAYS
        AS (extra_data->>'$.metadata.color[0]') STORED,
    timestamp INTEGER NOT NULL,
    extra_data TEXT,
    UNIQUE(flow_id, tag)
);
CREATE TABLE IF NOT EXISTS "anomaly" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    extra_data TEXT,
    UNIQUE(flow_id, timestamp)
);
CREATE TABLE IF NOT EXISTS "fileinfo" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    extra_data TEXT,
    UNIQUE(flow_id, timestamp)
);
CREATE TABLE IF NOT EXISTS "app-event" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    app_proto TEXT NOT NULL,
    extra_data TEXT,
    UNIQUE(flow_id, app_proto, timestamp)
);
CREATE INDEX IF NOT EXISTS "flow_ts_start_idx" ON flow(ts_start);
CREATE INDEX IF NOT EXISTS "flow_app_proto_idx" ON flow(app_proto);
CREATE INDEX IF NOT EXISTS "flow_src_ipport_idx" ON flow(src_ipport);
CREATE INDEX IF NOT EXISTS "flow_dest_ipport_idx" ON flow(dest_ipport);
CREATE INDEX IF NOT EXISTS "alert_tag_idx" ON alert(tag);
CREATE INDEX IF NOT EXISTS "alert_flow_id_idx" ON alert(flow_id);
CREATE INDEX IF NOT EXISTS "anomaly_flow_id_idx" ON anomaly(flow_id);
CREATE INDEX IF NOT EXISTS "fileinfo_flow_id_idx" ON fileinfo(flow_id);
CREATE INDEX IF NOT EXISTS "app-event_flow_id_idx" ON "app-event"(flow_id, app_proto);
