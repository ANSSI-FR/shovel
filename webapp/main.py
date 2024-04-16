#!/usr/bin/env python3
# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

import asyncio
import base64
import contextlib
import json

from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from database import Database


def row_to_dict(row) -> dict:
    row = dict(row)
    extra_data = json.loads(row.pop("extra_data"))
    row.update(extra_data)
    return row


async def index(request):
    context = {
        "request": request,
        "ctf_config": CTF_CONFIG,
    }
    return templates.TemplateResponse("index.html.jinja2", context)


async def api_flow_list(request):
    # Parse GET arguments
    ts_to = request.query_params.get("to", str(int(1e10)))
    services = request.query_params.getlist("service")
    app_proto = request.query_params.get("app_proto")
    tags = request.query_params.getlist("tag")
    if not ts_to.isnumeric():
        raise HTTPException(400)

    # Query flows and associated tags using filters
    query = """
        WITH fsrvs AS (SELECT value FROM json_each(?1)),
          ftags AS (SELECT value FROM json_each(?2))
        SELECT id, ts_start, ts_end, dest_ipport, app_proto,
          (SELECT GROUP_CONCAT(tag) FROM alert WHERE flow_id = flow.id) AS tags
        FROM flow WHERE ts_start <= ?3 AND (?4 IS NULL OR app_proto = ?4)
    """
    if services == ["!"]:
        # Filter flows related to no services
        query += "AND NOT (src_ipport IN fsrvs OR dest_ipport IN fsrvs)"
        services = sum(CTF_CONFIG["services"].values(), [])
    elif services:
        query += "AND (src_ipport IN fsrvs OR dest_ipport IN fsrvs)"
    if tags:
        # Relational division to get all flow_id matching all chosen tags
        query += """
            AND flow.id IN (
                SELECT flow_id FROM alert WHERE tag IN ftags GROUP BY flow_id
                HAVING COUNT(*) = (SELECT COUNT(*) FROM ftags)
            )
        """
    query += " ORDER BY ts_start DESC LIMIT 100"

    cursor = await database.execute(
        query, (json.dumps(services), json.dumps(tags), int(ts_to) * 1000, app_proto)
    )
    rows = await cursor.fetchall()
    flows = [dict(row) for row in rows]

    # Fetch application protocols
    cursor = await database.execute("SELECT DISTINCT app_proto FROM flow")
    rows = await cursor.fetchall()
    prs = [r["app_proto"] for r in rows if r["app_proto"] not in [None, "failed"]]

    # Fetch tags
    cursor = await database.execute(
        "SELECT tag, color FROM alert GROUP BY tag ORDER BY color"
    )
    rows = await cursor.fetchall()
    tags = [dict(row) for row in rows]

    return JSONResponse(
        {
            "flows": flows,
            "appProto": prs,
            "tags": tags,
        }
    )


async def api_flow_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow from database
    cursor = await database.execute(
        (
            "SELECT id, ts_start, ts_end, src_ipport, dest_ipport, dest_port, "
            "pcap_filename, proto, app_proto, extra_data "
            "FROM flow WHERE id = ?"
        ),
        [flow_id],
    )
    flow = await cursor.fetchone()
    if not flow:
        raise HTTPException(404)
    result = {"flow": row_to_dict(flow)}
    app_proto = result["flow"].get("app_proto")

    # Get associated fileinfo
    # See https://docs.suricata.io/en/suricata-6.0.9/file-extraction/file-extraction.html
    if app_proto in ["http", "http2", "smtp", "ftp", "nfs", "smb"]:
        cursor = await database.execute(
            "SELECT extra_data FROM fileinfo WHERE flow_id = ? ORDER BY id", [flow_id]
        )
        rows = await cursor.fetchall()
        result["fileinfo"] = [row_to_dict(f) for f in rows]

    # Get associated protocol metadata
    if app_proto and app_proto != "failed":
        q_proto = app_proto if app_proto != "http2" else "http"
        cursor = await database.execute(
            f"SELECT extra_data FROM {q_proto} WHERE flow_id = ? ORDER BY id",
            [flow_id],
        )
        rows = await cursor.fetchall()
        result[app_proto] = [row_to_dict(f) for f in rows]

    # Get associated alert
    if result["flow"]["alerted"]:
        cursor = await database.execute(
            "SELECT extra_data, color FROM alert WHERE flow_id = ? ORDER BY id",
            [flow_id],
        )
        rows = await cursor.fetchall()
        result["alert"] = [row_to_dict(f) for f in rows]

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_flow_raw_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow from database to get proto
    cursor = await database.execute("SELECT proto FROM flow WHERE id = ?", [flow_id])
    flow = await cursor.fetchone()
    if not flow:
        raise HTTPException(404)
    basepath = "static/{}store/".format(flow["proto"].lower())

    # Get associated raw data
    cursor = await database.execute(
        "SELECT server_to_client, sha256 FROM raw WHERE flow_id = ? ORDER BY count",
        [flow_id],
    )
    rows = await cursor.fetchall()
    result = []
    for r in rows:
        with open("{}/{}/{}".format(basepath, r["sha256"][:2], r["sha256"]), "rb") as f:
            data = base64.b64encode(f.read()).decode()
        result.append({"server_to_client": r["server_to_client"], "data": data})

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_replay_http(request):
    flow_id = request.path_params["flow_id"]

    # Get HTTP events
    cursor = await database.execute(
        "SELECT flow_id, extra_data FROM http WHERE flow_id = ? ORDER BY id",
        [flow_id],
    )
    rows = await cursor.fetchall()

    # For each HTTP request, load client payload if it exists
    data = []
    for row in rows:
        req = row_to_dict(row)
        req["rq_content"] = None
        if req["http_method"] in ["POST"]:
            # Get associated fileinfo
            cursor = await database.execute(
                "SELECT extra_data FROM fileinfo WHERE flow_id = ? ORDER BY id",
                [flow_id],
            )
            fileinfo_first_event = await cursor.fetchone()
            if not fileinfo_first_event:
                raise HTTPException(404)
            sha256 = json.loads(fileinfo_first_event["extra_data"]).get("sha256")
            if not sha256:
                raise HTTPException(500)

            # Load file
            path = f"static/filestore/{sha256[:2]}/{sha256}"
            with open(path, "rb") as f:
                req["rq_content"] = f.read()
        data.append(req)

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "http-replay.py.jinja2", context, media_type="text/plain"
    )


async def api_replay_raw(request):
    flow_id = request.path_params["flow_id"]

    # Get flow event
    cursor = await database.execute(
        "SELECT dest_ipport, proto FROM flow WHERE id = ?",
        [flow_id],
    )
    flow_event = await cursor.fetchone()
    if not flow_event:
        raise HTTPException(404)
    ip, port = flow_event["dest_ipport"].rsplit(":", 1)
    data = {
        "flow_id": flow_id,
        "ip": ip,
        "port": port,
        "dest_ipport": flow_event["dest_ipport"],
        "proto": flow_event["proto"],
    }

    # Get associated raw data
    cursor = await database.execute(
        "SELECT server_to_client, sha256 FROM raw WHERE flow_id = ? ORDER BY count",
        [flow_id],
    )
    rows = await cursor.fetchall()
    if not rows:
        raise HTTPException(404)

    # Load files
    data["raw_data"] = []
    proto = flow_event["proto"].lower()
    for row in rows:
        sc, sha256 = row["server_to_client"], row["sha256"]
        path = f"static/{proto}store/{sha256[:2]}/{sha256}"
        with open(path, "rb") as f:
            raw_data = f.read()
        if data["raw_data"] and data["raw_data"][-1][1] == sc and sc == 1:
            # Concat servers messages together
            data["raw_data"][-1][0] += raw_data
        else:
            data["raw_data"].append([raw_data, sc])

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "raw-replay.py.jinja2", context, media_type="text/plain"
    )


@contextlib.asynccontextmanager
async def lifespan(app):
    """
    Open database on startup and launch importer in background.
    Close database on exit.
    """
    await database.connect()
    if await database.is_readonly():
        print("SQLite database opened in read-only mode", flush=True)
        yield
    else:
        await database.update_ctf_config(CTF_CONFIG)
        db_task = asyncio.create_task(database.importer_task())
        yield
        db_task.cancel()
    await database.close()


# Load configuration from environment variables, then .env file
config = Config(".env")
DEBUG = config("DEBUG", cast=bool, default=False)
DATABASE_URL = config("DATABASE_URL", cast=str, default="file:database/database.db")
CTF_CONFIG = {
    "start_date": config("CTF_START_DATE", cast=str),
    "tick_length": config("CTF_TICK_LENGTH", cast=int),
    "services": {},
}
service_names = config("CTF_SERVICES", cast=CommaSeparatedStrings)
for name in service_names:
    ipports = config(f"CTF_SERVICE_{name.upper()}", cast=CommaSeparatedStrings)
    CTF_CONFIG["services"][name] = list(ipports)

# Define web application
database = Database(DATABASE_URL)
templates = Jinja2Templates(directory="templates")
app = Starlette(
    debug=DEBUG,
    routes=[
        Route("/", index),
        Route("/api/flow", api_flow_list),
        Route("/api/flow/{flow_id:int}", api_flow_get),
        Route("/api/flow/{flow_id:int}/raw", api_flow_raw_get),
        Route("/api/replay-http/{flow_id:int}", api_replay_http),
        Route("/api/replay-raw/{flow_id:int}", api_replay_raw),
        Mount(
            "/static",
            StaticFiles(directory="static", follow_symlink=True),
            name="static",
        ),
    ],
    lifespan=lifespan,
)
