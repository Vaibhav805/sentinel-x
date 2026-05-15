#!/bin/bash
# setup_ns.sh — Create veth pair + namespace for Sentinel-X testing
#
# Safe to re-run: tears down existing state before rebuilding.
# Run: sudo bash src/setup_ns.sh

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  Sentinel-X  ·  Network namespace setup"
echo "════════════════════════════════════════════════════════════"

# ── Tear down any leftover state ─────────────────────────────────────────────
echo ""
echo "[1/5] Cleaning up previous setup..."
ip netns del attack-ns 2>/dev/null && echo "  ✓ deleted attack-ns" || true
ip link del veth0      2>/dev/null && echo "  ✓ deleted veth0"     || true
# veth1 is deleted automatically when its peer veth0 is deleted, but be safe:
ip link del veth1      2>/dev/null || true

# ── Create namespace ─────────────────────────────────────────────────────────
echo ""
echo "[2/5] Creating network namespace 'attack-ns'..."
ip netns add attack-ns
echo "  ✓ attack-ns created"

# ── Create veth pair ─────────────────────────────────────────────────────────
echo ""
echo "[3/5] Creating veth pair veth0 ↔ veth1..."
ip link add veth0 type veth peer name veth1
ip link set veth1 netns attack-ns
echo "  ✓ veth0 on host,  veth1 moved into attack-ns"

# ── Configure both ends ──────────────────────────────────────────────────────
echo ""
echo "[4/5] Configuring interfaces..."

# Host side
ip addr add 10.0.0.1/24 dev veth0
ip link set veth0 up
echo "  ✓ veth0  10.0.0.1/24  UP"

# Namespace side
ip netns exec attack-ns ip addr add 10.0.0.2/24 dev veth1
ip netns exec attack-ns ip link set veth1 up
ip netns exec attack-ns ip link set lo    up
echo "  ✓ veth1  10.0.0.2/24  UP  (inside attack-ns)"

# ── Kernel settings ──────────────────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "  ✓ ip_forward=1"

# Raise BPF locked-memory limit for the current session
# (flux.py does this in Python too, but doing it here helps sudo contexts)
ulimit -l unlimited 2>/dev/null || true

# ── Connectivity check ───────────────────────────────────────────────────────
echo ""
echo "[5/5] Verifying connectivity (attack-ns → host)..."
if ip netns exec attack-ns ping -c 2 -W 1 10.0.0.1 > /dev/null 2>&1; then
    echo "  ✓ veth pair working — 10.0.0.2 ↔ 10.0.0.1"
else
    echo "  ✗ Ping failed — check your kernel networking settings"
    exit 1
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Setup complete."
echo ""
echo "  Interface map:"
echo "    Host     : veth0  (10.0.0.1)  ← XDP attaches here"
echo "    Namespace: veth1  (10.0.0.2)  inside attack-ns"
echo ""
echo "  ① Start bridge (terminal 1):"
echo "    python3 $PROJECT_DIR/src/bridge.py"
echo ""
echo "  ② Start Sentinel-X (terminal 2 — needs sudo for BPF):"
echo "    sudo $PROJECT_DIR/myenv/bin/python3 $PROJECT_DIR/src/flux.py"
echo ""
echo "  ③ Launch attack from attack-ns (terminal 3):"
echo "    sudo ip netns exec attack-ns hping3 -S -p 80 --flood --rand-source 10.0.0.1"
echo ""
echo "  ④ Start dashboard (terminal 4):"
echo "    cd $PROJECT_DIR && npm run dev   # or node server/server.js"
echo "════════════════════════════════════════════════════════════"