#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* ── Per-CPU counters ────────────────────────────────────────────────────── */
BPF_PERCPU_ARRAY(global_stats, u64, 1);   /* every pkt XDP sees            */
BPF_PERCPU_ARRAY(drop_stats,   u64, 1);   /* every pkt actually dropped    */

/* ── Bypass kill-switch ──────────────────────────────────────────────────── */
BPF_ARRAY(bypass_mode, u32, 1);

/* ── Entropy / telemetry tracking maps ──────────────────────────────────── */
BPF_HASH(ip_counts,   u32, u64, 65536);
BPF_HASH(port_counts, u16, u64, 1024);

/* ── Rate-limiter config (written from Python userspace) ─────────────────
 *
 *  rate_cfg[0]  = pps_limit   — packets/sec above which XDP starts dropping
 *  rate_cfg[1]  = drop_prob   — scaled 0-1000000 (1000000 = 100% drop)
 *                               Python sets this proportionally to excess rate.
 *  rate_cfg[2]  = flood_mode  — 1 = flood detected, use drop_prob; 0 = normal
 *
 *  This gives Python full control: it monitors the rate, computes how
 *  aggressive to drop, and writes the values.  XDP reads them atomically
 *  per packet — no locks needed because these are single-element arrays
 *  and we only need eventual consistency.
 * ─────────────────────────────────────────────────────────────────────── */
BPF_ARRAY(rate_cfg, u64, 3);

/* ── Per-second packet counter for rate estimation inside XDP ────────────
 *  [0] = packet count in current second window
 *  [1] = timestamp (seconds) of window start — stored as u64 nanoseconds
 * ─────────────────────────────────────────────────────────────────────── */
BPF_ARRAY(pps_window, u64, 2);

/* ── Perf event struct ───────────────────────────────────────────────────── */
struct packet_stats {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 pkt_len;
    __u8  proto;
    __u16 dst_port;
} __attribute__((packed));

/* ── LPM per-IP blacklist ─────────────────────────────────────────────────
 *  BPF_F_TABLE gives us full control of the key type — avoids the hidden
 *  key-wrapping of BPF_LPM_TRIE that caused [-Wincompatible-pointer-types]
 *  and "Invalid argument" at map-open time.
 * ─────────────────────────────────────────────────────────────────────── */
struct lpm4_key {
    u32 prefixlen;   /* bits — 32 = exact /32 host match                   */
    u32 addr;        /* IPv4 in native (LE on x86) byte order              */
};
BPF_F_TABLE("lpm_trie", struct lpm4_key, u32, blacklist_map, 65536,
            BPF_F_NO_PREALLOC);

/* ── Perf ring buffer ────────────────────────────────────────────────────── */
BPF_PERF_OUTPUT(events);

/* ── XDP entry point ─────────────────────────────────────────────────────── */
int xdp_flux_parser(struct xdp_md *ctx)
{
    int zero = 0, one = 1, two = 2;

    /* Count every packet */
    u64 *cnt = global_stats.lookup(&zero);
    if (cnt) lock_xadd(cnt, 1);

    /* ── Bypass kill-switch ─────────────────────────────────────────────── */
    u32 *bypass = bypass_mode.lookup(&zero);
    if (bypass && *bypass == 1) return XDP_PASS;

    /* ── Parse Ethernet / IP ────────────────────────────────────────────── */
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    /* ── Per-IP blacklist check ─────────────────────────────────────────── */
    struct lpm4_key bl_key = { .prefixlen = 32, .addr = iph->saddr };
    u32 *blocked = blacklist_map.lookup(&bl_key);
    if (blocked && *blocked == 1) {
        u64 *dc = drop_stats.lookup(&zero);
        if (dc) lock_xadd(dc, 1);
        return XDP_DROP;
    }

    /* ── FLOOD-MODE probabilistic drop ──────────────────────────────────
     *
     *  When Python sets flood_mode=1 it also sets drop_prob (0-1000000).
     *  We use the packet length as a cheap pseudo-random seed to decide
     *  whether to drop — no proper RNG needed at kernel speed.
     *
     *  The "random" value is derived from:
     *    iph->id (changes per packet) XOR iph->saddr low 16 bits
     *  mapped into 0-999999.
     *
     *  This distributes drops evenly across all source IPs — exactly
     *  what we need for a rand-source flood where per-IP blocking fails.
     * ────────────────────────────────────────────────────────────────── */
    u64 *flood_mode_p = rate_cfg.lookup(&two);
    if (flood_mode_p && *flood_mode_p == 1) {
        u64 *drop_prob_p = rate_cfg.lookup(&one);
        if (drop_prob_p && *drop_prob_p > 0) {
            /* Cheap deterministic "random" per packet — spread across IPs */
            u32 pseudo = (u32)bpf_ntohs(iph->id) ^ (u32)(iph->saddr & 0xFFFF);
            pseudo = pseudo * 2654435761u;  /* Knuth multiplicative hash   */
            u32 roll = pseudo % 1000000u;   /* 0 – 999999                  */
            if (roll < (u32)*drop_prob_p) {
                u64 *dc = drop_stats.lookup(&zero);
                if (dc) lock_xadd(dc, 1);
                return XDP_DROP;
            }
        }
    }

    /* ── Entropy tracking (non-dropped packets only) ────────────────────── */
    u32 src = iph->saddr;
    u64 *iv = ip_counts.lookup(&src);
    if (iv) { lock_xadd(iv, 1); }
    else    { u64 one_v = 1; ip_counts.update(&src, &one_v); }

    /* ── Transport parse ────────────────────────────────────────────────── */
    __u16 dst_port   = 0;
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    void *trans = (void *)iph + ip_hdr_len;
    if (trans > data_end) return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = trans;
        if ((void *)(tcp + 1) <= data_end)
            dst_port = bpf_ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = trans;
        if ((void *)(udp + 1) <= data_end)
            dst_port = bpf_ntohs(udp->dest);
    }

    if (dst_port > 0) {
        u16 dp = dst_port;
        u64 *pv = port_counts.lookup(&dp);
        if (pv) { lock_xadd(pv, 1); }
        else    { u64 one_v = 1; port_counts.update(&dp, &one_v); }
    }

    /* ── Emit to Python userspace via perf buffer ───────────────────────── */
    struct packet_stats stats = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .pkt_len  = bpf_ntohs(iph->tot_len),
        .proto    = iph->protocol,
        .dst_port = dst_port,
    };
    events.perf_submit(ctx, &stats, sizeof(stats));
    return XDP_PASS;
}