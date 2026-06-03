
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

// Flow key: IP address + port.
//   Forward entry:  ip = client_ip,  port = client_port (tcph->source on SYN)
//   Reverse entry:  ip = backend_ip, port = client_port (same port, different IP)
//
// Using (ip, port) instead of the full 4-tuple is sufficient because:
//   - daddr is always lb->ip on both forward and return paths (not discriminating)
//   - dport is always 80 on forward (constant) and ephemeral on return (== sport)
//   - (saddr, sport) uniquely identifies a connection from either direction
//
// Explicit pad: BPF verifier rejects map keys with uninitialised bytes.
// Always zero-init the struct with = {} before filling fields.
struct flow_key {
    __u32 ip;
    __u16 port;
    __u16 pad;
};

// Flow value: everything needed to rewrite headers in both directions.
//   backend_*: used by forward path packets after the first SYN
//   client_*:  used by return path to route reply back to the right client
struct flow_val {
    __u32 backend_ip;
    __u8  backend_mac[ETH_ALEN];
    __u8  pad1[2];
    __u32 client_ip;
    __u8  client_mac[ETH_ALEN];
    __u8  pad2[2];
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

// Incremented once per new connection (no existing flow entry).
// All subsequent packets use the flow table — counter never races per-packet.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rr_counter SEC(".maps");

// Dual-entry LRU hash. Two entries per connection:
//   { client_ip, client_port } → flow_val  (forward path lookup)
//   { backend_ip, client_port } → flow_val  (return path lookup)
//
// max_entries = 65536 * 2 = 131072 to account for two entries per connection.
// Each entry is sizeof(flow_key) + sizeof(flow_val) = 8 + 20 = 28 bytes
// → ~3.5 MB total.
//
// LRU evicts the least-recently-used entry when full. Both entries for a
// connection have the same access pattern so they age out together naturally.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_table SEC(".maps");


// ── 3. Checksum helpers (identical to phase 07) ───────────────────────────────

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    __u32 sum = 0;
    __u16 *p = (__u16 *)iph;

    #pragma unroll
    for (int i = 0; i < 10; i++)
        sum += p[i];

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    return ~(__u16)sum;
}

static __always_inline __u16 tcp_csum(struct iphdr  *iph,
                                       struct tcphdr *tcph,
                                       void          *data_end)
{
    __u16 ip_len    = bpf_ntohs(iph->tot_len);
    __u16 ihl_bytes = (__u16)(iph->ihl * 4);
    __u16 tcp_len   = ip_len - ihl_bytes;

    __u32 sum = 0;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr)       & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr)       & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);

    tcph->check = 0;
    __u16 *p    = (__u16 *)tcph;
    __u16 words = tcp_len >> 1;

    #pragma unroll
    for (int i = 0; i < 512; i++) {
        if (i >= words)
            break;
        if ((void *)((__u8 *)p + (i * 2) + 2) > data_end)
            break;
        sum += p[i];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    return ~(__u16)sum;
}

static __always_inline void copy_mac(__u8 *dst, __u8 *src)
{
    __builtin_memcpy(dst, src, ETH_ALEN);
}


// ── 4. XDP program ───────────────────────────────────────────────────────────

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

        // Forward lookup key: (client_ip, client_port).
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

            // Build the shared flow value — same content written into both
            // the forward and reverse entries.
            struct flow_val new_val = {};
            new_val.backend_ip = be->ip;
            __builtin_memcpy(new_val.backend_mac, be->mac, ETH_ALEN);
            new_val.client_ip  = iph->saddr;
            __builtin_memcpy(new_val.client_mac, eth->h_source, ETH_ALEN);

            // Entry 1 — forward key: (client_ip, client_port)
            // Looked up by every forward-path packet after this SYN.
            bpf_map_update_elem(&flow_table, &fwd_key, &new_val, BPF_ANY);

            // Entry 2 — reverse key: (backend_ip, client_port)
            // Looked up by the return path using (iph->saddr=backend_ip,
            // tcph->dest=client_port). No circular dependency — backend_ip
            // is known here from the selected backend.
            struct flow_key rev_key = {
                .ip   = be->ip,
                .port = tcph->source,
                .pad  = 0,
            };
            bpf_map_update_elem(&flow_table, &rev_key, &new_val, BPF_ANY);

            copy_mac(eth->h_dest,   be->mac);
            copy_mac(eth->h_source, lb->mac);
            iph->daddr = be->ip;
            iph->saddr = lb->ip;

        } else {
            // Existing connection — use the stored backend.
            copy_mac(eth->h_dest,   fval->backend_mac);
            copy_mac(eth->h_source, lb->mac);
            iph->daddr = fval->backend_ip;
            iph->saddr = lb->ip;
        }

        iph->check  = iph_csum(iph);
        tcph->check = tcp_csum(iph, tcph, data_end);
        return XDP_TX;

    } else {

        // ── RETURN PATH ──────────────────────────────────────────────────────
        //
        // Return packet from backend:
        //   iph->saddr = backend_ip
        //   tcph->dest = client_port  (client's original ephemeral port)
        //
        // Reverse key: (backend_ip, client_port) — written by forward path
        // at connection creation. Single O(1) lookup, no circular dependency.

        struct flow_key rev_key = {
            .ip   = iph->saddr,   // backend IP
            .port = tcph->dest,   // client's original port
            .pad  = 0,
        };

        struct flow_val *fval = bpf_map_lookup_elem(&flow_table, &rev_key);
        if (!fval)
            return XDP_PASS;   // no entry: predates XDP load or LRU-evicted

        copy_mac(eth->h_dest,   fval->client_mac);
        copy_mac(eth->h_source, lb->mac);
        iph->daddr = fval->client_ip;
        iph->saddr = lb->ip;

        iph->check  = iph_csum(iph);
        tcph->check = tcp_csum(iph, tcph, data_end);
        return XDP_TX;
    }
}


// ── 5. License ────────────────────────────────────────────────────────────────
char _license[] SEC("license") = "GPL";