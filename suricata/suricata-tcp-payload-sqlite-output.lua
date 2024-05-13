-- Copyright (C) 2024  ANSSI
-- SPDX-License-Identifier: GPL-2.0-or-later

-- This Suricata plugin logs TCP flows data to a SQLite database.

function init (args)
    local needs = {}
    needs["type"] = "streaming"
    needs["filter"] = "tcp"
    return needs
end

function setup (args)
    SCLogNotice("Initializing plugin TCP payload SQLite Output; author=ANSSI; license=GPL-2.0")

    -- open database in WAL mode and init schema
    local sqlite3 = require("lsqlite3")
    database = sqlite3.open(SCLogPath() .. "/payload.db")
    assert(database:exec([[
        PRAGMA journal_mode=wal;
        PRAGMA synchronous=off;
        CREATE TABLE IF NOT EXISTS raw (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            count INTEGER,
            server_to_client INTEGER,
            blob BLOB,
            UNIQUE(flow_id, count)
        );
        CREATE INDEX IF NOT EXISTS "raw_flow_id_idx" ON raw(flow_id);
    ]]) == sqlite3.OK)
    stmt = database:prepare("INSERT OR IGNORE INTO raw (flow_id, count, server_to_client, blob) values(?, ?, ?, ?);")

    -- packer counter for each flow
    flow_pkt_count = {}
    flow_pkt_count_total = 0
end

function log (args)
    -- create log entry
    local flow_id = SCFlowId()
    if flow_pkt_count[flow_id] == nil then
        flow_pkt_count[flow_id] = 0
    else
        flow_pkt_count[flow_id] = flow_pkt_count[flow_id] + 1
    end
    local count = flow_pkt_count[flow_id]
    flow_pkt_count_total = flow_pkt_count_total + 1
    local data, sb_open, sb_close, sb_ts, sb_tc = SCStreamingBuffer()
    if #data == 0 then
        return
    end
    local direction = "0"
    if sb_tc then
        direction = "1"
    end
    assert(stmt:reset() == sqlite3.OK)
    assert(stmt:bind_values(flow_id, count, direction, data) == sqlite3.OK)
    assert(stmt:step() == sqlite3.DONE)
end

function deinit (args)
    SCLogNotice("TCP flow logged: " .. flow_pkt_count_total)
    database:close()
end
