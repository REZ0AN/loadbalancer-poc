// xdp_lb.c
//
// Builds on phase 08 (dual-entry flow table). Two things change:
//
//   1. IP/TCP checksum: full recompute loop replaced with RFC 1624
//      incremental update. O(1), no loop, correct for any packet size.
//
//   2. Per-backend counters: new PERCPU_ARRAY map. Each CPU increments
//      its own slot with a plain store, no bus lock, no atomic.
//      Userspace sums per-CPU values in stats.sh.
//
// Everything else, dual-entry flow table, XDP_TX, xdpgeneric,
// direction detection, MAC rewrite, is identical to phase 08.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// ── 1. Structs ────────────────────────────────────────────────────────────────

struct endpoint {
    __u32 ip;
    __u8  mac[ETH_ALEN];
    __u8  pad[2];
};

struct flow_key {
    __u32 ip;
    __u16 port;
    __u16 pad;
};

struct flow_val {
    __u32 backend_ip;
    __u8  backend_mac[ETH_ALEN];
    __u8  pad1[2];
    __u32 client_ip;
    __u8  client_mac[ETH_ALEN];
    __u8  pad2[2];
};

// Per-backend counter — packets forwarded and bytes forwarded.
// Stored in a PERCPU_ARRAY so each CPU has its own copy.
struct backend_stats {
    __u64 packets;
    __u64 bytes;
};


// ── 2. BPF Maps ───────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct endpoint);
} lb_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct endpoint);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} backend_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rr_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_table SEC(".maps");

// PERCPU_ARRAY: one slot per backend index, one independent copy per CPU.
// No atomic needed — each CPU writes only its own slot.
// Userspace sums across CPUs to get the aggregate.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct backend_stats);
} backend_stats SEC(".maps");


// ── 3. RFC 1624 incremental checksum ─────────────────────────────────────────
//
// We change exactly two IP fields: saddr and daddr.
// RFC 1624 adjusts the existing checksum for one changed 32-bit word
// without touching anything else:
//
//   new_csum = ~(~old_csum + ~old_val + new_val)
//
// Applied twice (saddr then daddr) gives the correct updated checksum.
// Works identically for both IP checksum and TCP checksum — the TCP
// pseudo-header includes saddr + daddr, so the same delta applies.
//
// O(1). No loop. No payload scan. Correct for any packet size.

static __always_inline __u16 csum_diff4(__u32 old_val, __u32 new_val, __u16 old_check)
{
    __u32 sum = (~((__u32)old_check) & 0xffff)
              + ((~old_val >> 16) & 0xffff) + (~old_val & 0xffff)
              + (new_val >> 16)              + (new_val & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return ~(__u16)sum;
}


// ── 4. MAC copy helper ────────────────────────────────────────────────────────

static __always_inline void copy_mac(__u8 *dst, __u8 *src)
{
    __builtin_memcpy(dst, src, ETH_ALEN);
}


// ── 5. XDP program ───────────────────────────────────────────────────────────

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_ABORTED;

    __u32 zero = 0;

    struct endpoint *lb = bpf_map_lookup_elem(&lb_info, &zero);
    if (!lb)
        return XDP_ABORTED;

    if (tcph->dest == bpf_htons(80)) {

        // ── FORWARD PATH ─────────────────────────────────────────────────────

        struct flow_key fwd_key = {
            .ip   = iph->saddr,
            .port = tcph->source,
            .pad  = 0,
        };

        struct flow_val *fval = bpf_map_lookup_elem(&flow_table, &fwd_key);

        if (!fval) {
            // New connection — pick backend via round-robin.
            __u32 *rr = bpf_map_lookup_elem(&rr_counter, &zero);
            if (!rr) return XDP_ABORTED;

            __u32 *cnt = bpf_map_lookup_elem(&backend_count, &zero);
            if (!cnt || *cnt == 0) return XDP_PASS;

            __u32 idx = (*rr) % (*cnt);
            __sync_fetch_and_add(rr, 1);

            struct endpoint *be = bpf_map_lookup_elem(&backends, &idx);
            if (!be) return XDP_ABORTED;

            // Write forward entry: (client_ip, client_port) → flow_val
            struct flow_val new_val = {};
            new_val.backend_ip = be->ip;
            __builtin_memcpy(new_val.backend_mac, be->mac, ETH_ALEN);
            new_val.client_ip  = iph->saddr;
            __builtin_memcpy(new_val.client_mac, eth->h_source, ETH_ALEN);
            bpf_map_update_elem(&flow_table, &fwd_key, &new_val, BPF_ANY);

            // Write reverse entry: (backend_ip, client_port) → flow_val
            struct flow_key rev_key = {
                .ip   = be->ip,
                .port = tcph->source,
                .pad  = 0,
            };
            bpf_map_update_elem(&flow_table, &rev_key, &new_val, BPF_ANY);

            // Rewrite headers
            copy_mac(eth->h_dest,   be->mac);
            copy_mac(eth->h_source, lb->mac);

            __u32 old_saddr = iph->saddr;
            __u32 old_daddr = iph->daddr;
            iph->daddr = be->ip;
            iph->saddr = lb->ip;

            // RFC 1624 incremental update — save before rewrite, apply after
            iph->check  = csum_diff4(old_saddr, lb->ip,
                          csum_diff4(old_daddr, be->ip, iph->check));
            tcph->check = csum_diff4(old_saddr, lb->ip,
                          csum_diff4(old_daddr, be->ip, tcph->check));

            // PERCPU increment — no atomic, this CPU owns this slot
            struct backend_stats *s = bpf_map_lookup_elem(&backend_stats, &idx);
            if (s) {
                s->packets += 1;
                s->bytes   += bpf_ntohs(iph->tot_len);
            }

        } else {
            // Existing connection — use stored backend.
            copy_mac(eth->h_dest,   fval->backend_mac);
            copy_mac(eth->h_source, lb->mac);

            __u32 old_saddr = iph->saddr;
            __u32 old_daddr = iph->daddr;
            iph->daddr = fval->backend_ip;
            iph->saddr = lb->ip;

            iph->check  = csum_diff4(old_saddr, lb->ip,
                          csum_diff4(old_daddr, fval->backend_ip, iph->check));
            tcph->check = csum_diff4(old_saddr, lb->ip,
                          csum_diff4(old_daddr, fval->backend_ip, tcph->check));
        }

        return XDP_TX;

    } else {

        // ── RETURN PATH ──────────────────────────────────────────────────────

        struct flow_key rev_key = {
            .ip   = iph->saddr,
            .port = tcph->dest,
            .pad  = 0,
        };

        struct flow_val *fval = bpf_map_lookup_elem(&flow_table, &rev_key);
        if (!fval)
            return XDP_PASS;

        copy_mac(eth->h_dest,   fval->client_mac);
        copy_mac(eth->h_source, lb->mac);

        __u32 old_saddr = iph->saddr;
        __u32 old_daddr = iph->daddr;
        iph->daddr = fval->client_ip;
        iph->saddr = lb->ip;

        iph->check  = csum_diff4(old_saddr, lb->ip,
                      csum_diff4(old_daddr, fval->client_ip, iph->check));
        tcph->check = csum_diff4(old_saddr, lb->ip,
                      csum_diff4(old_daddr, fval->client_ip, tcph->check));

        return XDP_TX;
    }
}


// ── 6. License ────────────────────────────────────────────────────────────────
char _license[] SEC("license") = "GPL";