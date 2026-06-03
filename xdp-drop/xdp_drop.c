// Builds on phase 05: we still parse eth → IP → TCP in the same way.
// Two new things happen here:
//
//   1. Policy decision: drop any IPv4/TCP packet that is NOT destined
//      for our VIP port (80).  XDP_DROP eliminates the packet before the
//      kernel networking stack ever sees it, no skb, no conntrack, no
//      iptables traversal.
//
//   2. Counting: two BPF maps record how many packets were passed and
//      how many were dropped.  A userspace reader in loader.sh prints
//      those counters.  This is the first time we use BPF maps, the
//      primary mechanism for kernel ↔ userspace communication in BPF.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// ── 1. BPF Maps ──────────────────────────────────────────────────────────────

#define IDX_PASS  0
#define IDX_DROP  1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");


// ── 2. Helper: increment a counter in pkt_count ──────────────────────────────



static __always_inline void count(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&pkt_count, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}


// ── 3. XDP program ───────────────────────────────────────────────────────────

SEC("xdp")
int xdp_drop_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Parse Ethernet ───────────────────────────────────────────────────────
    // Identical to phase 05. Bounds check before any field access.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    // Pass non-IPv4 without counting.
    // ARP is required for the topology to work (MAC resolution).
    // We must never drop ARP — the namespaces would lose connectivity.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        count(IDX_PASS);
        return XDP_PASS;
    }

    // ── Parse IPv4 ───────────────────────────────────────────────────────────
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;

    // Pass non-TCP (ICMP ping must keep working — we need it for debugging).
    if (iph->protocol != IPPROTO_TCP) {
        count(IDX_PASS);
        return XDP_PASS;
    }

    // ── Parse TCP ────────────────────────────────────────────────────────────
    // iph->ihl * 4 gives the actual IP header length in bytes (see phase 05).
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_ABORTED;

    // ── Policy decision ──────────────────────────────────────────────────────
    //
    // veth-lb receives traffic from TWO directions:
    //
    //   Forward path (client → lb):
    //     tcph->dest   = 80          (client targeting our VIP port)
    //     tcph->source = ephemeral   (e.g. 54321)
    //
    //   Return path (backend → lb):
    //     tcph->source = 80          (backend replying from its server port)
    //     tcph->dest   = ephemeral   (the client's original source port)
    //

    if (tcph->dest != bpf_htons(80) && tcph->source != bpf_htons(80)) {
        count(IDX_DROP);
        return XDP_DROP;
    }

    // Port 80 — pass to the kernel stack (and to any existing LB rules).
    count(IDX_PASS);
    return XDP_PASS;
}


// ── 4. License ───────────────────────────────────────────────────────────────
char _license[] SEC("license") = "GPL";