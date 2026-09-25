"""
dashboard/server.py

Live web dashboard for the SAF reference implementation. Every number this
serves is produced by the real, unmodified protocol code in saf/ (real
Mosquitto broker, real SAFGateway, real SAFClient, real HMAC/ASCON crypto)
via the telemetry bus (saf/telemetry.py) and the runtime verifier
(saf/runtime_verifier.py) that live-checks each real exchange.

This dashboard deliberately does not shell out to the Scyther binary: the
.spdl models in scyther/ are pre-made, static models, not something this
simulation generates, so "running Scyther" here would just replay a fixed,
already-documented result (see README.md section 1.3) rather than show
anything live. What *is* live is the "hardened" toggle on Publish: it
switches the real client/gateway code between the as-specified alpha
binding (HMAC_k(x||c) -- the one saf_phase2.spdl finds Niagree/Nisynch
failing for) and the hardened binding verified all-pass in
saf_phase2_hardened_final.spdl (HMAC_k(x||c||identifier_msg||t_msg) plus a
MAC'd broker reply) -- saf/runtime_verifier.py re-derives both, live, from
the real bytes each exchange actually used.

Run (after `pip install fastapi "uvicorn[standard]"` and starting/allowing
this to start a local Mosquitto broker on 127.0.0.1:1883):

    python3 -m dashboard.server

Then open http://127.0.0.1:8000/
"""

import asyncio
import logging
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from saf.gateway import SAFGateway  # noqa: E402
from saf.client import SAFClient  # noqa: E402
from saf.state_store import SAFStateStore  # noqa: E402
from saf.telemetry import bus  # noqa: E402
from saf import runtime_verifier  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("saf.dashboard")

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883
MOSQUITTO_CONF = REPO_ROOT / "mosquitto_conf" / "mosquitto.conf"

app = FastAPI(title="SAF Live Protocol Dashboard")

state = {
    "gateway": None,       # type: Optional[SAFGateway]
    "store": None,         # type: Optional[SAFStateStore]
    "clients": {},         # type: Dict[str, SAFClient]
    "broker_started_by_us": False,
}


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


def _ensure_broker_running() -> None:
    if _port_open(BROKER_HOST, BROKER_PORT):
        log.info(f"[dashboard] Mosquitto already listening on {BROKER_HOST}:{BROKER_PORT}, reusing it")
        return
    log.info("[dashboard] No broker detected -- starting mosquitto from mosquitto_conf/mosquitto.conf")
    try:
        subprocess.Popen(
            ["mosquitto", "-c", str(MOSQUITTO_CONF)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        state["broker_started_by_us"] = True
    except FileNotFoundError:
        log.error("[dashboard] 'mosquitto' binary not found on PATH. Install it "
                   "(macOS: brew install mosquitto) and re-run, or start it yourself "
                   "with: mosquitto -c mosquitto_conf/mosquitto.conf")
        return
    for _ in range(30):
        if _port_open(BROKER_HOST, BROKER_PORT):
            log.info("[dashboard] broker is up")
            return
        time.sleep(0.2)
    log.error("[dashboard] broker did not come up in time")


@app.on_event("startup")
def on_startup() -> None:
    _ensure_broker_running()
    runtime_verifier.ensure_running(bus=bus)
    store = SAFStateStore()
    gw = SAFGateway(host=BROKER_HOST, port=BROKER_PORT, store=store)
    gw.start()
    state["gateway"] = gw
    state["store"] = store
    bus.publish("dashboard", "server_started", broker=f"{BROKER_HOST}:{BROKER_PORT}")


@app.on_event("shutdown")
def on_shutdown() -> None:
    for c in state["clients"].values():
        try:
            c.disconnect()
        except Exception:
            pass
    if state["gateway"] is not None:
        state["gateway"].stop()


# --------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------- #

class RegisterRequest(BaseModel):
    client_id: str


class PublishRequest(BaseModel):
    client_id: str
    topic: str = "sensors/demo"
    payload: str = "temp=23.5C"
    encrypt: bool = False
    tamper: bool = False
    replay: bool = False
    hardened: bool = False


def _get_or_create_client(client_id: str) -> SAFClient:
    c = state["clients"].get(client_id)
    if c is None:
        c = SAFClient(client_id, host=BROKER_HOST, port=BROKER_PORT)
        c.connect()
        state["clients"][client_id] = c
    return c


@app.post("/api/register")
async def api_register(req: RegisterRequest):
    loop = asyncio.get_event_loop()

    def _do():
        c = _get_or_create_client(req.client_id)
        ok = c.register(timeout=5.0)
        return {"ok": ok, "client_id": req.client_id,
                "x_hex": c.x.hex() if c.x else None,
                "k_hex": c.k.hex() if c.k else None,
                "c": c.c}

    return await loop.run_in_executor(None, _do)


@app.post("/api/publish")
async def api_publish(req: PublishRequest):
    loop = asyncio.get_event_loop()

    def _do():
        c = state["clients"].get(req.client_id)
        if c is None or not c.registered:
            return {"ok": False, "error": "client must register (Phase 1) first"}
        replay_id = None
        if req.replay:
            # genuinely reuse this client's last *broker-recorded* (Approved)
            # identifier_msg, so this actually exercises the broker's real
            # duplicate-identifier defense (Section VI-A) rather than sending
            # a never-before-seen id that happens to collide with nothing.
            replay_id = getattr(c, "_last_approved_identifier_msg", None)
            if replay_id is None:
                return {"ok": False, "error": "no prior Approved publish from this client to "
                                               "replay -- publish normally (and get Approved) first"}
        status = c.publish(
            req.topic, req.payload.encode("utf-8"), encrypt=req.encrypt,
            tamper_alpha=req.tamper, replay_identifier=replay_id, hardened=req.hardened,
        )
        if status is not None and status.status == "Approved":
            c._last_approved_identifier_msg = status.identifier_msg
        return {
            "ok": status is not None,
            "status": status.status if status else "TIMEOUT",
            "reason": status.reason if status else "no response from gateway",
        }

    return await loop.run_in_executor(None, _do)


@app.get("/api/status")
async def api_status():
    gw = state["gateway"]
    store = state["store"]
    return {
        "broker": f"{BROKER_HOST}:{BROKER_PORT}",
        "broker_reachable": _port_open(BROKER_HOST, BROKER_PORT),
        "clients_registered": list(state["clients"].keys()),
        "gateway_decisions": len(gw.decision_log) if gw else 0,
        "store_client_count": len(store.clients) if store else 0,
    }


@app.get("/api/history")
async def api_history(n: int = 200):
    return [e.to_dict() for e in bus.recent(n)]


# --------------------------------------------------------------------- #
# WebSocket: live telemetry stream
# --------------------------------------------------------------------- #

@app.websocket("/ws")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"kind": "backlog", "events": [e.to_dict() for e in bus.recent(200)]})
    q = bus.subscribe()
    loop = asyncio.get_event_loop()
    try:
        while True:
            evt = await loop.run_in_executor(None, q.get)
            await websocket.send_json(evt.to_dict())
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(q)


# --------------------------------------------------------------------- #
# Static frontend
# --------------------------------------------------------------------- #

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/favicon.ico")
async def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard.server:app", host="127.0.0.1", port=8000, reload=False)
