#!/usr/bin/env python3
"""
Sentinel-X flux.py — Fixed version
Fixes:
  1. _choose_interface() is now actually CALLED (was defined but INTERFACE was hardcoded)
  2. BRIDGE_URL → localhost:4000  (flux.py runs on HOST, not inside attack-ns)
  3. Fast-block: 0.5s window with a dedicated high-rate trip wire so floods are
     caught in the first window, not after 10+ training windows.
  4. _compute_features() no longer resets maps BEFORE reading top-IP in _enforce
  5. Dashboard pipeline: emit() sends to the default namespace (no /bridge here);
     bridge.py forwards to Node.js /bridge correctly.
  6. process_event now accumulates per-src-IP counters in Python too, giving
     _enforce a live per-IP rate to work from even during training.
"""

import resource
resource.setrlimit(resource.RLIMIT_MEMLOCK,
                   (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

from bcc import BPF
import os, sys, signal, socket, struct, math, time, logging
import ctypes as ct
import threading
import random
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Optional, Dict

import numpy as np
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
import socketio
import psutil

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
def _iface_exists(name: str) -> bool:
    return os.path.exists(f"/sys/class/net/{name}")

def _choose_interface() -> str:
    """
    Priority:
      1. XDP_INTERFACE env var (explicit override)
      2. veth0 on host (correct hook — packets enter from attack-ns side)
      3. veth1 inside attack-ns (fallback with warning)
    Raises SystemExit with a clear message if nothing is found.
    """
    env_iface = os.environ.get("XDP_INTERFACE")
    if env_iface:
        if _iface_exists(env_iface):
            print(f"[IFACE] Using XDP_INTERFACE override: {env_iface}")
            return env_iface
        raise SystemExit(
            f"ERROR: XDP_INTERFACE={env_iface!r} set but interface not found.\n"
            "  → Did you run `sudo bash src/setup_ns.sh` first?")

    if _iface_exists("veth0"):
        print("[IFACE] Found veth0 (host side) — correct XDP hook.")
        return "veth0"

    if _iface_exists("veth1"):
        print(
            "WARNING: veth0 not present; falling back to veth1.\n"
            "  This usually means flux.py is running INSIDE attack-ns.\n"
            "  For correct drop behaviour run flux.py on the HOST where veth0 lives.")
        return "veth1"

    raise SystemExit(
        "ERROR: Neither veth0 nor veth1 found.\n"
        "  → Run `sudo bash src/setup_ns.sh` to create the veth pair first.\n"
        "  → Or set XDP_INTERFACE=<ifname> to point at an existing interface.")

# ── Resolve interface at import time so the error fires immediately ──────────
INTERFACE        = _choose_interface()          # FIX 1: was hardcoded "veth0"
BPF_SRC          = "src/flux.c"
JUDGE_MODEL_PATH = "models/xgb_judge.json"

# FIX 2: flux.py runs on the HOST, so bridge.py is reachable on localhost.
# The old value (10.0.0.1:4000) only works when flux.py is inside attack-ns.
BRIDGE_URL       = "http://localhost:4000"

# ── Timing ───────────────────────────────────────────────────────────────────
# FIX 3: shorter detection window so floods are caught fast.
WINDOW_TIME      = 0.5          # was 2.0 s — halved for faster response
TRAIN_WINDOWS    = 20           # still ~10 s of learning (20 × 0.5 s)
CONTAMINATION    = 0.05
EMIT_INTERVAL    = 1.0
PRINT_INTERVAL   = 1.0

PROB_DROP        = 0.85
PROB_IGNORE      = 0.30
TTL_MINUTES      = 5
SWEEP_INTERVAL   = 30.0
SAMPLE_RATE      = 0.01

# ── Trip-wire: block any IP whose per-window packet count exceeds this value
# even during training (before Sentry is ready).  Prevents "only 1 drop" issue.
FLOOD_TRIPWIRE   = 500          # pkts/window — adjust to your hping3 rate

os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename="logs/sentinel.log", level=logging.INFO,
                    format="%(asctime)s %(message)s")
grey_log = logging.getLogger("grey")

# ─────────────────────────────────────────────────────────────────────────────
# PERF EVENT STRUCT — must match flux.c struct packet_stats exactly
# ─────────────────────────────────────────────────────────────────────────────
class PktStats(ct.Structure):
    _pack_   = 1
    _fields_ = [
        ("src_ip",   ct.c_uint32),
        ("dst_ip",   ct.c_uint32),
        ("pkt_len",  ct.c_uint16),
        ("proto",    ct.c_uint8),
        ("dst_port", ct.c_uint16),
    ]

STRUCT_SIZE = ct.sizeof(PktStats)   # 13 bytes

class LpmKey(ct.Structure):
    # Matches C struct lpm4_key: { u32 prefixlen; u32 addr; } = 8 bytes
    _fields_ = [("prefixlen", ct.c_uint32), ("addr", ct.c_uint32)]

def ip_to_native(ip_str: str) -> int:
    return struct.unpack("=I", socket.inet_aton(ip_str))[0]

def native_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("=I", n))

# ─────────────────────────────────────────────────────────────────────────────
# THREAD-SAFE BPF OPS
# ─────────────────────────────────────────────────────────────────────────────
_map_lock = threading.Lock()

def bpf_add(ip_nat: int) -> bool:
    with _map_lock:
        key = LpmKey(prefixlen=32, addr=ip_nat)
        try:
            b["blacklist_map"][key] = ct.c_uint32(1)
            v = b["blacklist_map"][key]   # read-back verify
            if v is None or int(v.value) != 1:
                print(f"[WARN] bpf_add verify failed {native_to_ip(ip_nat)}")
                return False
            return True
        except Exception as e:
            print(f"[WARN] bpf_add {native_to_ip(ip_nat)}: {e}")
            return False

def bpf_del(ip_nat: int):
    with _map_lock:
        key = LpmKey(prefixlen=32, addr=ip_nat)
        try:    del b["blacklist_map"][key]
        except KeyError: pass
        except Exception as e: print(f"[WARN] bpf_del: {e}")

def bpf_set_bypass(enabled: bool):
    with _map_lock:
        try:    b["bypass_mode"][ct.c_uint32(0)] = ct.c_uint32(1 if enabled else 0)
        except Exception as e: print(f"[WARN] bypass: {e}")

def bpf_set_flood_mode(enabled: bool, drop_prob: float = 0.0):
    """
    Write flood-mode config into the BPF rate_cfg array so XDP can act
    on it immediately for every subsequent packet — no IP matching needed.

    rate_cfg layout (u64 array):
      [0] = pps_limit  (unused by XDP; kept for Python bookkeeping)
      [1] = drop_prob  scaled 0–1_000_000  (1_000_000 = 100% drop)
      [2] = flood_mode 0 or 1
    """
    with _map_lock:
        try:
            prob_scaled = ct.c_uint64(int(min(max(drop_prob, 0.0), 1.0) * 1_000_000))
            mode_val    = ct.c_uint64(1 if enabled else 0)
            b["rate_cfg"][ct.c_uint32(1)] = prob_scaled
            b["rate_cfg"][ct.c_uint32(2)] = mode_val
        except Exception as e:
            print(f"[WARN] bpf_set_flood_mode: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# KERNEL COUNTERS
# ─────────────────────────────────────────────────────────────────────────────
def k_total() -> int:
    try:    return int(sum(b["global_stats"][ct.c_uint32(0)]))
    except: return 0

def k_drops() -> int:
    try:    return int(sum(b["drop_stats"][ct.c_uint32(0)]))
    except: return 0

def map_entropy(map_name: str) -> tuple:
    try:
        c = {k.value: int(v.value)
             for k, v in b[map_name].items() if int(v.value) > 0}
        if not c: return 0.0, 0, 0
        t = sum(c.values())
        e = -sum((v/t)*math.log2(v/t) for v in c.values())
        return e, len(c), t
    except: return 0.0, 0, 0

def reset_entropy():
    try:    b["ip_counts"].clear();   b["port_counts"].clear()
    except: pass

# ─────────────────────────────────────────────────────────────────────────────
# SOCKET.IO CLIENT  (connects to bridge.py on localhost:4000)
# FIX 4 / dashboard pipeline: emit to default namespace — bridge.py forwards
# everything received here to Node.js /bridge correctly.
# ─────────────────────────────────────────────────────────────────────────────
sio = socketio.Client(
    reconnection=False,          # we manage reconnection ourselves
    logger=False, engineio_logger=False)
_sio_ok  = False
_sio_lock = threading.Lock()   # guards sio.emit() — client is not thread-safe

@sio.event
def connect():
    global _sio_ok; _sio_ok = True
    print("[SIO] Connected to bridge on localhost:4000")

@sio.event
def disconnect():
    global _sio_ok; _sio_ok = False
    print("[SIO] Disconnected from bridge — will retry")

@sio.on("cmd_unblock")
def on_unblock(data):
    try:    _unblock(ip_to_native(data.get("ip", "")), "manual restore")
    except Exception as e: print(f"[SIO] unblock err: {e}")

@sio.on("cmd_set_prob_drop")
def on_prob(data):
    global PROB_DROP
    PROB_DROP = max(0.0, min(1.0, float(data.get("value", PROB_DROP))))
    print(f"[SIO] PROB_DROP → {PROB_DROP:.2f}")

@sio.on("cmd_set_bypass")
def on_bypass(data):
    bpf_set_bypass(bool(data.get("enabled", False)))

def emit(ev: str, d: dict):
    """Thread-safe fire-and-forget emit to bridge (default namespace)."""
    if not _sio_ok: return
    with _sio_lock:
        try:    sio.emit(ev, d)
        except: pass

def _sio_thread():
    """Keep trying to connect to bridge.py; reconnect on drop."""
    while True:
        if not _sio_ok:
            try:
                if sio.connected:
                    try: sio.disconnect()
                    except: pass
                sio.connect(BRIDGE_URL, transports=["websocket"],
                            wait_timeout=5)
            except Exception as e:
                pass   # bridge not up yet — retry in 3 s
        time.sleep(3)

# ─────────────────────────────────────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class State:
    sentry: IsolationForest = field(default_factory=lambda: IsolationForest(
        contamination=CONTAMINATION, n_estimators=100, random_state=42))
    trained:   bool = False
    history:   list = field(default_factory=list)
    judge:     Optional[XGBClassifier] = None
    judge_ok:  bool = False

    pkt_sizes:    deque = field(default_factory=lambda: deque(maxlen=10000))
    proto_window: deque = field(default_factory=lambda: deque(maxlen=10000))

    win_start:  float = 0.0
    win_k_base: int   = 0
    last_feats: list  = field(default_factory=lambda: [0.0]*7)

    timers:  Dict[int, dict] = field(default_factory=dict)
    retests: Dict[int, int]  = field(default_factory=dict)

    rb_pkts:     int = 0
    n_blocked:   int = 0
    n_unblocked: int = 0
    n_grey:      int = 0
    n_fp:        int = 0
    blocked_ips: set = field(default_factory=set)
    last_print:  float = 0.0

    ip_window_counts: Counter = field(default_factory=Counter)

    # ── Flood-mode state ─────────────────────────────────────────────────
    # When a volumetric/rand-source flood is detected (high rate + high entropy),
    # we engage XDP-level probabilistic drop via rate_cfg BPF array.
    # This works regardless of source IP — essential for --rand-source floods.
    flood_mode:      bool  = False          # is flood-mode currently active?
    flood_drop_prob: float = 0.0            # 0.0-1.0 current drop probability
    baseline_rate:   float = 0.0            # learned normal pps from training
    baseline_ip_ent: float = 0.0            # learned normal ip entropy

S = State()

def load_judge():
    if not os.path.exists(JUDGE_MODEL_PATH):
        print("[WARN] No judge model — Sentry-only mode"); return None
    try:
        m = XGBClassifier(); m.load_model(JUDGE_MODEL_PATH)
        print("[OK] Judge model loaded"); return m
    except Exception as e:
        print(f"[WARN] Judge load failed: {e}"); return None

# ─────────────────────────────────────────────────────────────────────────────
# BLOCK / UNBLOCK
# ─────────────────────────────────────────────────────────────────────────────
def _block(ip_nat: int, prob: float = 1.0):
    if ip_nat in S.blocked_ips: return
    if not bpf_add(ip_nat):     return
    S.blocked_ips.add(ip_nat)
    S.n_blocked += 1
    now = time.monotonic()
    S.timers[ip_nat] = {"t0": now, "last": now, "prob": prob}
    ip_str = native_to_ip(ip_nat)
    print(f"\n  ▶ KERNEL BLACKLIST  {ip_str}  p={prob:.3f}")
    print(f"    XDP_DROP armed — kernel_drops will now climb\n")
    emit("ip_blocked", {"ip": ip_str, "score": round(prob*100, 1)})

def _unblock(ip_nat: int, reason: str):
    bpf_del(ip_nat)
    S.blocked_ips.discard(ip_nat)
    S.timers.pop(ip_nat, None)
    S.retests.pop(ip_nat, None)
    S.n_unblocked += 1
    ip_str = native_to_ip(ip_nat)
    print(f"\n  ◀ UNBLOCKED  {ip_str}  reason={reason}\n")
    emit("ip_unblocked", {"ip": ip_str, "reason": reason})

# ─────────────────────────────────────────────────────────────────────────────
# FEATURES
# FIX 6: Do NOT reset maps inside _compute_features; reset happens AFTER
# _enforce reads the top-IP from ip_counts, preventing a race condition where
# the map was cleared before _enforce could read it.
# ─────────────────────────────────────────────────────────────────────────────
def _compute_features() -> list:
    now     = time.monotonic()
    elapsed = max(now - S.win_start, 1e-6)
    kn      = k_total()
    rate    = max(kn - S.win_k_base, 0) / elapsed

    ip_ent, uips, _ = map_entropy("ip_counts")
    pt_ent, _,    _ = map_entropy("port_counts")
    avg_sz = float(np.mean(S.pkt_sizes)) if S.pkt_sizes else 0.0
    pc = Counter(S.proto_window); tp = sum(pc.values()) or 1

    # Window base advances here; maps reset happens in _enforce after top-IP read
    S.win_start  = now
    S.win_k_base = kn

    return [ip_ent, pt_ent, rate, uips, avg_sz,
            pc.get(6, 0)/tp, pc.get(17, 0)/tp]

# ─────────────────────────────────────────────────────────────────────────────
# ENFORCEMENT
# ─────────────────────────────────────────────────────────────────────────────
def _enforce(feats: list):
    """Called every WINDOW_TIME after training. Decides whether to block top offender."""
    if not S.trained: return

    is_anomaly = (S.sentry.predict([feats])[0] == -1)

    # Always reset the window counters at the end of an enforcement cycle
    # (we've already read feats from _compute_features which snapshots the window).
    top_ip = None
    try:
        if S.ip_window_counts:
            top_ip = S.ip_window_counts.most_common(1)[0][0]
        else:
            counts = {k.value: int(v.value)
                      for k, v in b["ip_counts"].items() if int(v.value) > 0}
            if counts:
                top_ip = max(counts, key=counts.get)
    except Exception:
        pass
    finally:
        S.ip_window_counts.clear()
        reset_entropy()
        S.pkt_sizes.clear()
        S.proto_window.clear()

    if not is_anomaly: return          # traffic looks normal — nothing to block
    if top_ip is None: return          # no source IP data

    if top_ip in S.blocked_ips: return

    prob: Optional[float] = None
    if S.judge_ok:
        try:    prob = float(S.judge.predict_proba([feats])[0][1])
        except: pass

    ip_str = native_to_ip(top_ip)
    if prob is None:
        # No judge model — sentry anomaly alone is enough to block
        _block(top_ip, 1.0)
    elif prob >= PROB_DROP:
        _block(top_ip, prob)
    elif prob <= PROB_IGNORE:
        S.n_fp += 1
        print(f"  FP-ignored {ip_str} p={prob:.3f}")
    else:
        S.n_grey += 1
        grey_log.info("GREY ip=%s prob=%.4f rate=%.1f", ip_str, prob, feats[2])


# ── Flood-mode thresholds ────────────────────────────────────────────────────
# A rand-source flood has HIGH rate AND HIGH ip_entropy (many unique IPs).
# We use both to distinguish from legitimate high-rate traffic (CDN, etc.).
FLOOD_RATE_MULTIPLIER = 3.0    # rate must be >3× baseline to trigger
FLOOD_ENTROPY_FLOOR   = 10.0   # ip_entropy > 10 bits = many unique sources
FLOOD_RAMPUP_START    = 0.50   # start dropping at 50% excess rate
FLOOD_MAX_DROP        = 0.97   # cap drop probability at 97% (preserve 3% for monitoring)


def _compute_flood_drop_prob(rate: float, ip_ent: float) -> float:
    """
    Returns drop probability 0.0–FLOOD_MAX_DROP based on how far the current
    rate exceeds the learned baseline.  High entropy (rand-source) shifts the
    curve steeper — we need to drop more aggressively when every packet has
    a different source IP and per-IP blocking is useless.

    Logic:
      excess_ratio = rate / max(baseline, 1)
      If excess_ratio < FLOOD_RAMPUP_START threshold → 0 (not a flood)
      If excess_ratio >= threshold → linear ramp up to FLOOD_MAX_DROP
      High entropy → multiply excess ratio by 1.5 (ramp faster)
    """
    baseline = max(S.baseline_rate, 1.0)
    ratio    = rate / baseline

    if ratio < FLOOD_RAMPUP_START or ip_ent < FLOOD_ENTROPY_FLOOR:
        return 0.0

    # Entropy bonus: rand-source floods get faster ramp-up
    entropy_factor = 1.5 if ip_ent > 12.0 else 1.0

    # Linear ramp: at 3× baseline with high entropy → ~80% drop
    # at 5× → ~97% (capped)
    prob = min((ratio - 1.0) / (FLOOD_RATE_MULTIPLIER * entropy_factor), 1.0)
    return min(prob * FLOOD_MAX_DROP, FLOOD_MAX_DROP)


def _tripwire_check(feats: list):
    """
    Runs every window (training AND active).

    Two complementary strategies:
    A) Per-IP tripwire — block any single IP sending ≥ FLOOD_TRIPWIRE pkts/window.
       Catches single-source floods fast, even before Sentry is trained.

    B) Flood-mode rate limiter — if rate is >> baseline AND ip_entropy is high
       (rand-source attack), engage XDP probabilistic drop immediately.
       This is the ONLY effective defence against --rand-source floods because
       per-IP blocking is useless when every packet has a different source.
    """
    rate   = feats[2]
    ip_ent = feats[0]

    # ── A: per-IP tripwire ──────────────────────────────────────────────────
    if S.ip_window_counts:
        top_ip, top_cnt = S.ip_window_counts.most_common(1)[0]
        if top_ip not in S.blocked_ips and top_cnt >= FLOOD_TRIPWIRE:
            ip_str = native_to_ip(top_ip)
            print(f"\n  ⚡ TRIPWIRE  {ip_str}  {top_cnt} pkts/window — instant block\n")
            _block(top_ip, 1.0)

    # ── B: flood-mode rate limiter (rand-source defence) ───────────────────
    # We only engage if we have a learned baseline (> 0) so training-phase
    # noise does not accidentally trigger flood mode.
    if S.baseline_rate <= 0.0:
        return   # still in training; no baseline yet

    drop_prob = _compute_flood_drop_prob(rate, ip_ent)

    if drop_prob > 0.0:
        if not S.flood_mode:
            S.flood_mode = True
            print(f"\n  🌊 FLOOD MODE ENGAGED  "
                  f"rate={rate:.0f}pps  ip_ent={ip_ent:.2f}  "
                  f"baseline={S.baseline_rate:.0f}pps  "
                  f"drop_prob={drop_prob*100:.1f}%")
            print(f"     XDP probabilistic drop ACTIVE — "
                  f"dropping ~{drop_prob*100:.0f}% of ALL packets kernel-side\n")
        elif abs(drop_prob - S.flood_drop_prob) > 0.05:
            # Update if probability changed meaningfully
            print(f"  🌊 FLOOD MODE  drop_prob adjusted: "
                  f"{S.flood_drop_prob*100:.1f}% → {drop_prob*100:.1f}%  "
                  f"rate={rate:.0f}pps")

        S.flood_drop_prob = drop_prob
        bpf_set_flood_mode(True, drop_prob)

    else:
        if S.flood_mode:
            S.flood_mode      = False
            S.flood_drop_prob = 0.0
            bpf_set_flood_mode(False, 0.0)
            print(f"\n  ✅ FLOOD MODE CLEARED  rate={rate:.0f}pps  "
                  f"ip_ent={ip_ent:.2f}  — resuming normal operation\n")

# ─────────────────────────────────────────────────────────────────────────────
# FEATURE LOOP
# ─────────────────────────────────────────────────────────────────────────────
def _reset_window():
    """Reset all per-window accumulators. Called at the end of every window."""
    S.ip_window_counts.clear()
    reset_entropy()
    S.pkt_sizes.clear()
    S.proto_window.clear()


def _feature_loop():
    while True:
        time.sleep(WINDOW_TIME)
        try:
            feats = _compute_features()
            S.last_feats = feats
            kt = k_total(); kd = k_drops()

            # Trip-wire + flood-mode check runs every window BEFORE reset
            _tripwire_check(feats)

            if not S.trained:
                S.history.append(feats)
                n = len(S.history)
                print(f"  LEARNING [{n:>2}/{TRAIN_WINDOWS}]  "
                      f"rate={feats[2]:>10.1f}pps  "
                      f"ip_ent={feats[0]:.3f}  "
                      f"kernel={kt:,}  kdrops={kd:,}")
                if n >= TRAIN_WINDOWS:
                    X = np.array(S.history)
                    S.sentry.fit(X)
                    S.trained = True
                    print("\n" + "═"*60)
                    print("  SENTRY TRAINED — Active-drop mode ARMED")
                    labels = ["ip_ent","pt_ent","rate","uIPs","avgSz","tcp","udp"]
                    for i, lbl in enumerate(labels):
                        col = X[:,i]
                        print(f"    {lbl:>7}: "
                              f"min={col.min():>10.2f}  "
                              f"max={col.max():>10.2f}  "
                              f"mean={col.mean():>10.2f}")
                    print("═"*60 + "\n")
                    emit("sentry_trained", {"windows": TRAIN_WINDOWS})
                    # Record baseline rate and entropy so flood-mode
                    # thresholds are relative to the learned "normal" traffic.
                    S.baseline_rate   = float(X[:, 2].mean())   # mean pps
                    S.baseline_ip_ent = float(X[:, 0].mean())   # mean ip_entropy
                    print(f"  Baseline: rate={S.baseline_rate:.1f}pps  "
                          f"ip_ent={S.baseline_ip_ent:.3f}")
                # FIX: reset window state after every training window so
                # features for the next window start from a clean slate.
                _reset_window()
            else:
                # _enforce reads ip_window_counts then resets everything
                # via its own finally block — no extra reset needed here.
                _enforce(feats)
        except Exception as e:
            print(f"[WARN] feature_loop: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY EMIT THREAD  — feeds dashboard via bridge.py → Node.js
# ─────────────────────────────────────────────────────────────────────────────
def _emit_loop():
    prev_kt = k_total()
    prev_kd = k_drops()
    while True:
        time.sleep(EMIT_INTERVAL)
        try:
            now   = time.monotonic()
            kt    = k_total()
            kd    = k_drops()
            pps   = max(kt - prev_kt, 0)
            dpps  = max(kd - prev_kd, 0)
            prev_kt = kt
            prev_kd = kd

            bl = []
            for ip_nat, meta in list(S.timers.items()):
                ttl_rem = max(0, TTL_MINUTES*60 - (now - meta["last"]))
                bl.append({
                    "ip":     native_to_ip(ip_nat),
                    "score":  round(meta.get("prob", 1.0) * 100, 1),
                    "ttl":    int(ttl_rem),
                    "status": "1% Sampling" if ip_nat in S.retests
                              else "Active Drop",
                })

            drop_pct = round(kd / max(kt, 1) * 100, 2)
            payload = {
                "ts":           int(now * 1000),
                "pps":          pps,
                "drop_pps":     dpps,
                "kernel_total": kt,
                "kernel_drops": kd,
                "drop_pct":     drop_pct,
                "drop_efficiency": drop_pct,   # alias for dashboard gauge
                "cpu_pct":      psutil.cpu_percent(interval=None),
                "ram_pct":      psutil.virtual_memory().percent,
                "rb_events":    S.rb_pkts,
                "fp_saved":     S.n_fp,
                "grey_count":   S.n_grey,
                "unblocked":    S.n_unblocked,
                "blocked_count": len(S.blocked_ips),
                "prob_drop":    PROB_DROP,
                "sentry_ready":   S.trained,
                "judge_ready":    S.judge_ok,
                "flood_mode":     S.flood_mode,
                "flood_drop_pct": round(S.flood_drop_prob * 100, 1),
                "baseline_rate":  round(S.baseline_rate, 1),
                "blocklist":      bl,
            }
            emit("telemetry", payload)
        except Exception as e:
            print(f"[WARN] emit_loop: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# TTL SWEEPER
# ─────────────────────────────────────────────────────────────────────────────
def _sweep_loop():
    ttl = TTL_MINUTES * 60
    while True:
        time.sleep(SWEEP_INTERVAL)
        now = time.monotonic()
        for ip_nat, meta in list(S.timers.items()):
            if now - meta["last"] >= ttl:
                _unblock(ip_nat, "ttl_expired")

# ─────────────────────────────────────────────────────────────────────────────
# PERF BUFFER CALLBACK
# ─────────────────────────────────────────────────────────────────────────────
def process_event(cpu, data, size):
    if size < STRUCT_SIZE: return
    try:
        pkt = ct.cast(data, ct.POINTER(PktStats)).contents
    except:
        return

    S.rb_pkts += 1
    S.pkt_sizes.append(pkt.pkt_len)
    S.proto_window.append(pkt.proto)

    src_nat = pkt.src_ip   # already native byte order from kernel

    # Accumulate Python-side per-IP window counter (used by _enforce + tripwire)
    S.ip_window_counts[src_nat] += 1

    # 1% re-test for blocked IPs
    if (src_nat in S.blocked_ips and S.judge_ok and S.trained
            and random.random() < SAMPLE_RATE):
        S.retests[src_nat] = S.retests.get(src_nat, 0) + 1
        try:
            prob = float(S.judge.predict_proba([S.last_feats])[0][1])
            if prob < PROB_IGNORE:
                _unblock(src_nat, f"1%-gate p={prob:.3f}")
            elif src_nat in S.timers:
                S.timers[src_nat]["last"] = time.monotonic()
        except:
            pass

    # Throttled terminal print (once per PRINT_INTERVAL)
    now = time.monotonic()
    if now - S.last_print >= PRINT_INTERVAL:
        S.last_print = now
        f = S.last_feats
        kt = k_total(); kd = k_drops()
        kd_snap = k_drops()
        if not S.trained:
            status = "LEARNING"
        elif S.flood_mode:
            status = f"🌊 FLOOD DROP {S.flood_drop_prob*100:.0f}%"
        elif S.blocked_ips:
            status = "⛔ IP-BLOCKED"
        else:
            status = "NORMAL"
        proto_s = {6:"TCP", 17:"UDP"}.get(pkt.proto, f"p={pkt.proto}")
        drop_rate_pct = kd_snap / max(kt, 1) * 100
        flood_info = (f"  drop_prob={S.flood_drop_prob*100:.0f}%"
                      if S.flood_mode else "")
        print(f"[{status:<28}]  "
              f"rate={f[2]:>10.1f}pps  "
              f"ip_ent={f[0]:.3f}  "
              f"uIPs={int(f[3]):>6}  "
              f"kdrops={kd_snap:,}  "
              f"eff={drop_rate_pct:.1f}%"
              f"{flood_info}")

# ─────────────────────────────────────────────────────────────────────────────
# SHUTDOWN
# ─────────────────────────────────────────────────────────────────────────────
def shutdown(sig, frame):
    print("\n[SENTINEL-X] Shutting down...")
    # Disarm flood-mode drop before detaching XDP so last packets pass through
    bpf_set_flood_mode(False, 0.0)
    try:    b.remove_xdp(INTERFACE, 0)
    except: pass
    kt = k_total(); kd = k_drops()
    print(f"\n  ── Final Summary ──────────────────────────────────")
    print(f"  Kernel total (every pkt XDP saw) : {kt:>14,}")
    print(f"  Kernel drops (XDP_DROP confirmed): {kd:>14,}")
    print(f"  Drop efficiency                  : {kd/max(kt,1)*100:>13.2f}%")
    print(f"  IPs autonomously blocked         : {S.n_blocked:>14,}")
    print(f"  IPs unblocked (TTL/1%-gate)      : {S.n_unblocked:>14,}")
    print(f"  False positives prevented        : {S.n_fp:>14,}")
    if S.blocked_ips:
        print(f"\n  Still blocked:")
        for ip_nat in sorted(S.blocked_ips):
            m = S.timers.get(ip_nat, {})
            dur = time.monotonic() - m.get("t0", time.monotonic())
            print(f"    {native_to_ip(ip_nat):<16} blocked {dur:.0f}s ago")
    try:    sio.disconnect()
    except: pass
    sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    S.judge    = load_judge()
    S.judge_ok = S.judge is not None

    print(f"\n[SENTINEL-X] Selected XDP interface : {INTERFACE}")
    print(f"[SENTINEL-X] Bridge URL             : {BRIDGE_URL}")
    print(f"[SENTINEL-X] Detection window       : {WINDOW_TIME}s")
    print(f"[SENTINEL-X] Flood trip-wire        : {FLOOD_TRIPWIRE} pkts/window")
    print(f"[SENTINEL-X] Loading BPF on '{INTERFACE}'...")

    b  = BPF(src_file=BPF_SRC)
    fn = b.load_func("xdp_flux_parser", BPF.XDP)
    b.attach_xdp(INTERFACE, fn, 0)
    print(f"[SENTINEL-X] XDP attached to {INTERFACE} ✓")

    S.win_start  = time.monotonic()
    S.win_k_base = k_total()

    for fn_t, name in [
        (_sio_thread,   "sio-client"),
        (_feature_loop, "feature-window"),
        (_emit_loop,    "telemetry-emit"),
        (_sweep_loop,   "ttl-sweeper"),
    ]:
        threading.Thread(target=fn_t, daemon=True, name=name).start()
        print(f"[SENTINEL-X] Thread started: {name}")

    print(f"\n[SENTINEL-X] Connecting to bridge at {BRIDGE_URL}")
    print(f"[SENTINEL-X] Training: {TRAIN_WINDOWS}×{WINDOW_TIME}s windows "
          f"({TRAIN_WINDOWS*WINDOW_TIME:.0f}s total)\n")

    b["events"].open_perf_buffer(process_event, page_cnt=512)
    while True:
        b.perf_buffer_poll(timeout=100)