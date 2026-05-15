#!/usr/bin/env python3
"""
bridge.py — runs on HOST (not inside attack-ns)

  flux.py  →  connects to localhost:4000 (default namespace "/")
  bridge.py →  relays every event to Node.js on localhost:3001  namespace "/bridge"
  Node.js dashboard subscribes to socket.io namespace "/bridge"

FIX: the original code had a namespace mismatch.
  • bpf_server (the server that flux.py connects to) listens on the DEFAULT
    namespace ("/") — flux.py never specifies a namespace, so that is correct.
  • node_client connects to Node.js on the "/bridge" namespace — correct.
  • The bug was that node_client.on("cmd_*") handlers used the default namespace
    of the CLIENT object, but the connection was on "/bridge", so the handlers
    never fired.  Fixed by registering them on the "/bridge" namespace explicitly
    using the Namespace object.
"""

import socketio
import eventlet
import eventlet.wsgi
import threading
import time

# ── Server that flux.py connects TO (default namespace) ──────────────────────
bpf_server = socketio.Server(
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)
bpf_app = socketio.WSGIApp(bpf_server)

# ── Client that connects TO Node.js /bridge ───────────────────────────────────
node_client = socketio.Client(
    reconnection=True,
    reconnection_attempts=0,
    reconnection_delay=1,
    reconnection_delay_max=5,
    logger=False,
    engineio_logger=False,
)

_node_ok = False

# ── flux.py → bridge events ───────────────────────────────────────────────────
@bpf_server.event
def connect(sid, environ):
    print(f"[BRIDGE] flux.py connected  sid={sid}")

@bpf_server.event
def disconnect(sid):
    print(f"[BRIDGE] flux.py disconnected  sid={sid}")

def _fwd(ev, d):
    """Forward an event from flux.py → Node.js /bridge."""
    if _node_ok:
        try:
            # Emit on the /bridge namespace so Node.js receives it
            node_client.emit(ev, d, namespace="/bridge")
        except Exception as e:
            print(f"[BRIDGE] fwd error ({ev}): {e}")

@bpf_server.on("telemetry")
def _(sid, d): _fwd("telemetry", d)

@bpf_server.on("ip_blocked")
def _(sid, d): _fwd("ip_blocked", d)

@bpf_server.on("ip_unblocked")
def _(sid, d): _fwd("ip_unblocked", d)

@bpf_server.on("sentry_trained")
def _(sid, d): _fwd("sentry_trained", d)

@bpf_server.on("cmd_ack")
def _(sid, d): _fwd("cmd_ack", d)

# ── Node.js → bridge (commands sent back to flux.py) ─────────────────────────
# FIX: register handlers on the "/bridge" namespace explicitly.
@node_client.on("cmd_unblock", namespace="/bridge")
def _(d):
    bpf_server.emit("cmd_unblock", d)

@node_client.on("cmd_set_prob_drop", namespace="/bridge")
def _(d):
    bpf_server.emit("cmd_set_prob_drop", d)

@node_client.on("cmd_set_bypass", namespace="/bridge")
def _(d):
    bpf_server.emit("cmd_set_bypass", d)

# ── Node.js connection lifecycle ──────────────────────────────────────────────
@node_client.on("connect", namespace="/bridge")
def _node_connect():
    global _node_ok
    _node_ok = True
    print("[BRIDGE] Connected to Node.js :3001/bridge")

@node_client.on("disconnect", namespace="/bridge")
def _node_disconnect():
    global _node_ok
    _node_ok = False
    print("[BRIDGE] Disconnected from Node.js :3001/bridge — will retry")

def _node_loop():
    """Keep trying to connect to Node.js; reconnect if dropped."""
    while True:
        if not _node_ok:
            try:
                node_client.connect(
                    "http://localhost:3001",
                    namespaces=["/bridge"],
                    transports=["websocket"],
                    wait_timeout=5,
                )
            except Exception as e:
                # Expected while Node.js is not yet running
                pass
        time.sleep(3)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[BRIDGE] Listening on 0.0.0.0:4000  (flux.py connects here)")
    print("[BRIDGE] Relaying to Node.js :3001/bridge")
    threading.Thread(target=_node_loop, daemon=True).start()
    eventlet.wsgi.server(
        eventlet.listen(("0.0.0.0", 4000)),
        bpf_app,
        log_output=False,
    )