# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

import asyncio
import ipaddress
import json
import re
import traceback
from functools import lru_cache

import aiosqlite

# List of possible application-layer protocols in Suricata
# suricata -c suricata.yaml --list-app-layer-protos
SUPPORTED_PROTOCOLS = [
    "bittorrent-dht",
    "dcerpc",
    "dhcp",
    "dnp3",
    "dns",
    "enip",
    "ftp",
    "ftp-data",
    "http",
    "http2",
    "ike",
    "ikev2",
    "imap",
    "krb5",
    "modbus",
    "mqtt",
    "nfs",
    "ntp",
    "pgsql",
    "quic",
    "rdp",
    "rfb",
    "sip",
    "smb",
    "smtp",
    "snmp",
    "ssh",
    "telnet",
    "tftp",
    "tls",
]

# Collect pcap filename for each flow
# This is an ugly hack to circumvent an upstream issue in Suricata
flow_pcap: dict = {}


@lru_cache
def sc_ip_format(sc_ipaddr: str) -> str:
    ip = ipaddress.ip_address(sc_ipaddr)
    if ip.version == 6:
        return f"[{ip.compressed}]"
    else:
        return f"{ip.compressed}"


async def load_event(con, line: bytes) -> None:
    """
    Add one event from eve.json to the SQL database
    Use regex rather than JSON parsing for performance reasons.
    """
    event_type = re.search(rb"\"event_type\":\"([^\"]+)\"", line).group(1).decode()
    if event_type == "flow":
        src_ip = re.search(rb"\"src_ip\":\"([^\"]+)\"", line).group(1).decode()
        dest_ip = re.search(rb"\"dest_ip\":\"([^\"]+)\"", line).group(1).decode()
        app_proto_m = re.search(rb"\"app_proto\":\"([^\"]+)\"", line)
        app_proto = app_proto_m.group(1).decode() if app_proto_m else None
        flow_id = re.search(rb"\"flow_id\":(\d+)", line).group(1).decode()
        pcap_filename = re.search(rb"\"pcap_filename\":\"([^\"]+)\"", line).group(1)
        assert not app_proto or app_proto in SUPPORTED_PROTOCOLS + [
            "failed"
        ], f"app_proto refers to an unsupported protocol: {app_proto}"
        pcap_filename = flow_pcap.pop(flow_id, pcap_filename)
        await con.execute(
            "INSERT OR IGNORE INTO flow (id, src_ip, src_port, "
            "dest_ip, dest_port, pcap_filename, proto, app_proto, "
            "extra_data) "
            "values(?1->>'flow_id', ?2, ?1->>'src_port', ?3, "
            "?1->>'dest_port', ?4, ?1->>'proto', ?1->>'app_proto', ?1->'flow')",
            (
                line,
                sc_ip_format(src_ip),
                sc_ip_format(dest_ip),
                pcap_filename.decode(),
            ),
        )
    elif event_type in ["alert", "anomaly", "fileinfo"] + SUPPORTED_PROTOCOLS:
        # Collect pcap_filename
        flow_id = re.search(rb"\"flow_id\":(\d+)", line).group(1).decode()
        pcap_filename = re.search(rb"\"pcap_filename\":\"([^\"]+)\"", line).group(1)
        flow_pcap[flow_id] = pcap_filename

        # Insert event
        await con.execute(
            f"INSERT OR IGNORE INTO '{event_type}' (flow_id, extra_data) "
            f"values(?1->>'flow_id', ?1->'{event_type}')",
            (line,),
        )


class Database:
    def __init__(self, database_uri: str) -> None:
        self.database_uri = database_uri
        self.con = None

    async def connect(self):
        self.con = await aiosqlite.connect(self.database_uri, uri=True)
        self.con.row_factory = aiosqlite.Row
        # WAL journal mode allows multiple concurrent readers
        await self.con.execute("PRAGMA journal_mode=wal")
        await self.con.execute("PRAGMA synchronous=normal")
        try:
            await self.init_database_structure()
        except aiosqlite.OperationalError as e:
            raise RuntimeError(
                f"unable to create database '{self.database_uri}'"
            ) from e

    async def is_readonly(self) -> bool:
        assert self.con is not None, "database connection closed"
        try:
            # This statement has no effects on a writable database
            await self.con.execute("pragma user_version=0")
            return False
        except aiosqlite.OperationalError:
            return True

    async def close(self):
        assert self.con is not None, "database connection closed"
        await self.con.close()

    async def execute(self, *args, **kwargs):
        assert self.con is not None, "database connection closed"
        return await self.con.execute(*args, **kwargs)

    async def init_database_structure(self):
        assert self.con is not None, "database connection closed"
        # TODO: when SQLite 3.42 is broadly available, use UNIXEPOCH('subsec')
        await self.con.executescript(
            """
            CREATE TABLE IF NOT EXISTS ctf_config (
                id INTEGER PRIMARY KEY,
                start_date TEXT,
                ts_start INTEGER GENERATED ALWAYS
                    AS ((JULIANDAY(start_date) - 2440587.5) * 86400000),
                tick_length INTEGER,
                services TEXT
            );
            CREATE TABLE IF NOT EXISTS checkpoint (
                id INTEGER PRIMARY KEY,
                eve_idx INTEGER,
                tcp_idx INTEGER,
                udp_idx INTEGER
            );
            CREATE TABLE IF NOT EXISTS flow (
                id INTEGER NOT NULL PRIMARY KEY,
                ts_start INTEGER GENERATED ALWAYS
                    AS ((JULIANDAY(SUBSTR((extra_data->>'start'), 1, 26))
                    - 2440587.5) * 86400000) STORED,
                ts_end INTEGER GENERATED ALWAYS
                    AS ((JULIANDAY(SUBSTR((extra_data->>'end'), 1, 26))
                    - 2440587.5) * 86400000) STORED,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                src_ipport TEXT GENERATED ALWAYS
                    AS (src_ip || ':' || IFNULL(src_port, 'None')),
                dest_ip TEXT NOT NULL,
                dest_port INTEGER,
                dest_ipport TEXT GENERATED ALWAYS
                    AS (dest_ip || ':' || IFNULL(dest_port, 'None')),
                pcap_filename TEXT,
                proto TEXT NOT NULL,
                app_proto TEXT,
                extra_data TEXT
            );
            CREATE TABLE IF NOT EXISTS alert (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                tag TEXT GENERATED ALWAYS
                    AS (extra_data->>'metadata.tag[0]') STORED,
                color TEXT GENERATED ALWAYS
                    AS (extra_data->>'metadata.color[0]') STORED,
                extra_data TEXT,
                FOREIGN KEY(flow_id) REFERENCES flow (id),
                UNIQUE(flow_id, tag)
            );
            CREATE TABLE IF NOT EXISTS raw (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                count INTEGER,
                server_to_client INTEGER,
                sha256 TEXT,
                FOREIGN KEY(flow_id) REFERENCES flow (id),
                UNIQUE(flow_id, count)
            );
            """
        )
        for e in ["anomaly", "fileinfo"] + SUPPORTED_PROTOCOLS:
            await self.con.execute(
                f"""
                CREATE TABLE IF NOT EXISTS "{e}" (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER NOT NULL,
                    timestamp INTEGER GENERATED ALWAYS
                        AS ((JULIANDAY(SUBSTR((extra_data->>'timestamp'), 1, 26))
                        - 2440587.5) * 86400000) STORED,
                    extra_data TEXT,
                    FOREIGN KEY(flow_id) REFERENCES flow (id),
                    UNIQUE(flow_id, timestamp)
                );
                """
            )

        # Create indexes for non-unique values
        await self.con.executescript(
            'CREATE INDEX IF NOT EXISTS "flow_ts_start_idx" ON flow(ts_start);'
            'CREATE INDEX IF NOT EXISTS "flow_app_proto_idx" ON flow(app_proto);'
            'CREATE INDEX IF NOT EXISTS "flow_src_ipport_idx" ON flow(src_ipport);'
            'CREATE INDEX IF NOT EXISTS "flow_dest_ipport_idx" ON flow(dest_ipport);'
            'CREATE INDEX IF NOT EXISTS "alert_tag_idx" ON alert(tag);'
        )
        for e in ["alert", "anomaly", "fileinfo", "raw"] + SUPPORTED_PROTOCOLS:
            await self.con.execute(
                f'CREATE INDEX IF NOT EXISTS "{e}_flow_id_idx" ON "{e}"(flow_id);'
            )

    async def update_ctf_config(self, ctf_config: dict):
        """
        Update database with configuration given through env vars (for Grafana).
        """
        assert self.con is not None, "database connection closed"
        await self.con.execute("BEGIN TRANSACTION")
        services = json.dumps(ctf_config["services"])
        await self.con.execute(
            "INSERT OR REPLACE INTO ctf_config (id, start_date, tick_length, services) "
            "values(1, ?, ?, ?)",
            (ctf_config["start_date"], ctf_config["tick_length"], services),
        )
        await self.con.execute("COMMIT")

    async def fill_database(self):
        assert self.con is not None, "database connection closed"
        await self.con.execute("BEGIN TRANSACTION")
        cursor = await self.con.execute(
            "SELECT eve_idx, tcp_idx, udp_idx FROM checkpoint"
        )
        eve_idx, tcp_idx, udp_idx = await cursor.fetchone() or [0, 0, 0]
        if eve_idx == 0:
            print("Starting initial eve.json import, please be patient...", flush=True)

        # eve.json contains one event per line
        with open("../suricata/output/eve.json", "rb") as f:
            f.seek(eve_idx)
            line_count = 0
            for line in f:
                if not line:
                    break
                try:
                    await load_event(self.con, line)
                except (AttributeError, aiosqlite.OperationalError):
                    break  # eve.json ends with a partial JSON
                eve_idx += len(line)
                line_count += 1
        if line_count:
            print(f"{line_count} events loaded from eve.json", flush=True)

        with open("../suricata/output/tcpstore.log", "r") as f:
            f.seek(tcp_idx)
            line_count = 0
            for line in f:
                if not line or not line.endswith("\n"):
                    break
                flow_id, count, server_to_client, h = line.strip().split(",")
                await self.con.execute(
                    "INSERT OR IGNORE INTO raw (flow_id, count, server_to_client, "
                    "sha256) values(?, ?, ?, ?)",
                    (flow_id, int(count), int(server_to_client), h),
                )
                tcp_idx += len(line)
                line_count += 1
        if line_count:
            print(f"{line_count} chunks loaded from tcpstore.log", flush=True)

        with open("../suricata/output/udpstore.log", "r") as f:
            f.seek(udp_idx)
            line_count = 0
            for line in f:
                if not line or not line.endswith("\n"):
                    break
                flow_id, count, server_to_client, h = line.strip().split(",")
                await self.con.execute(
                    "INSERT OR IGNORE INTO raw (flow_id, count, server_to_client, "
                    "sha256) values(?, ?, ?, ?)",
                    (flow_id, int(count), int(server_to_client), h),
                )
                udp_idx += len(line)
                line_count += 1
        if line_count:
            print(f"{line_count} chunks loaded from udpstore.log", flush=True)

        await self.con.execute(
            "INSERT OR REPLACE INTO checkpoint (id, eve_idx, tcp_idx, udp_idx) "
            "values(1, ?, ?, ?)",
            (eve_idx, tcp_idx, udp_idx),
        )
        await self.con.execute("COMMIT")

    async def importer_task(self):
        """
        Load events from eve.json and fill SQL database
        """
        while True:
            try:
                await self.fill_database()
            except FileNotFoundError:
                await self.con.execute("ROLLBACK")
                print("Suricata output not found, retrying in 1s", flush=True)
            except Exception:
                print(traceback.format_exc(), flush=True)
                return

            # Sleeping 1 second before trying to pull new data again
            await asyncio.sleep(1)
