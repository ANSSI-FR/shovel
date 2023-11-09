-- Copyright (C) 2023  ANSSI
-- SPDX-License-Identifier: GPL-3.0-only

function init (args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup (args)
    -- udpstore.log contains (flow_id, direction, sha256) tuples
    local logfilename = SCLogPath() .. "/udpstore.log"
    logfile = assert(io.open(logfilename, "a"))

    -- udpstore folder contains raw data
    foldername = SCLogPath() .. "/udpstore/"
    for i=0,255 do
        istr = string.format("%02x", i)
        os.execute("mkdir -p " .. foldername .. istr)
    end

    -- packer counter for each flow
    flow_pkt_count = {}
    flow_pkt_count_total = 0
end

function log (args)
    local sha = require("suricata/lua/sha2")

    -- drop if not UDP (17)
    -- https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    local ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()
    if proto ~= 17 then
        return
    end

    -- get packet direction
    local ipver, srcip_flow, dstip_flow, proto, sp_flow, dp_flow = SCFlowTuple()
    local direction = "1"
    if srcip == srcip_flow and dstip == dstip_flow and sp == sp_flow and dp == dp_flow then
        direction = "0"
    end

    -- create log entry
    local flow_id = SCFlowId()
    local flow_id_str = string.format("%.0f", flow_id)
    if flow_pkt_count[flow_id] == nil then
        flow_pkt_count[flow_id] = 0
    else
        flow_pkt_count[flow_id] = flow_pkt_count[flow_id] + 1
    end
    local count = flow_pkt_count[flow_id]
    flow_pkt_count_total = flow_pkt_count_total + 1
    local data = SCPacketPayload()
    if #data == 0 then
        return
    end
    local hash = sha.sha256(data)
    logfile:write(flow_id_str .. "," .. count .. "," .. direction .. "," .. hash .. "\n")

    -- save data
    local filename = foldername .. string.sub(hash, 1, 2) .. "/" .. hash
    local datafile = assert(io.open(filename, "w"))
    datafile:write(data)
    datafile:close()
end

function deinit (args)
    SCLogNotice("UDP flow logged: " .. flow_pkt_count_total)
    logfile:close()
end
