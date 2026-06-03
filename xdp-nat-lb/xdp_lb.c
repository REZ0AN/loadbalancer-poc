// Attaches to veth-lb inside the "lb" network namespace.
// Takes full ownership of packet forwarding — no iptables, no IPVS,
// no nftables.  All forwarding decisions happen at the XDP hook,
// before the kernel networking stack is involved.
//
// Forward path (client → lb):
//   1. Pick backend via source-port hash
//   2. Rewrite eth->h_dest  → backend MAC
//   3. Rewrite eth->h_source → lb MAC
//   4. Rewrite iph->daddr   → backend IP
//   5. Rewrite iph->saddr   → lb IP
//   6. Recalculate IP + TCP checksums
//   7. Return XDP_TX
//
// Return path (backend → lb):
//   1. Rewrite eth->h_dest  → client MAC
//   2. Rewrite eth->h_source → lb MAC
//   3. Rewrite iph->daddr   → client IP
//   4. iph->saddr stays as lb IP (already set by forward path)
//   5. Recalculate IP + TCP checksums
//   6. Return XDP_TX
//
// Attach with xdpgeneric (skb) mode , required for XDP_TX on veth.
// See loader.sh and docs/xdp-nat-lb.md for the full explanation.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// ── 1. Endpoint struct ────────────────────────────────────────────────────────
//
// Shared layout for lb_info, client_info, and backends map values.
//
// ip:     __be32 in network byte order — written directly into iph->saddr /
//         iph->daddr without any byte swap.
// mac:    6-byte Ethernet address.
// pad[2]: explicit alignment padding. Without it the compiler may insert
//         implicit padding that differs between kernel and userspace, causing
//         bpftool map update to write fields at wrong offsets.

struct endpoint {
    __u32 ip;
    __u8  mac[ETH_ALEN];
    __u8  pad[2];
};


// ── 2. BPF Maps ───────────────────────────────────────────────────────────────
//
// All maps are BPF_MAP_TYPE_ARRAY.  Arrays are:
//   - Pre-allocated: no dynamic memory allocation on lookup.
//   - Zero-initialised: unset entries are safely zero.
//   - O(1) lookup by integer index.
// We use ARRAY (not HASH) because all keys are small integers.
// Phase 08 introduces BPF_MAP_TYPE_LRU_HASH for the flow table.

// lb's own IP + MAC — needed on both forward and return paths.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct endpoint);
} lb_info SEC(".maps");

// client IP + MAC — needed on the return path to rewrite daddr + eth->h_dest.
// Phase 08 replaces this single-client map with an LRU flow table that
// supports any number of simultaneous clients.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct endpoint);
} client_info SEC(".maps");

// Backend pool — up to 8 {ip, mac} entries indexed 0..N-1.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct endpoint);
} backends SEC(".maps");

// How many backends are registered (written by loader.sh).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} backend_count SEC(".maps");

// Connection counter — incremented once per new TCP connection (SYN).
// Used by stats.sh to count total connections processed.
// NOT used for backend selection (see source-port hash below).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rr_counter SEC(".maps");


// ── 3. IP header checksum ─────────────────────────────────────────────────────
//
// Full recompute from scratch (RFC 791):
//   1. Zero the check field (so it doesn't skew the sum)
//   2. Sum all 16-bit words of the 20-byte header
//   3. Fold carry bits into the lower 16 bits
//   4. One's complement (bitwise NOT)
//
// We fix the iteration count at 10 (10 × 16-bit words = 20 bytes = minimum
// IPv4 header with ihl=5).  IP options are not used in our netns topology.
// The two-step fold (rather than a while loop) is verifier-safe because it
// is straight-line code with no branches.

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


// ── 4. TCP checksum ───────────────────────────────────────────────────────────
//
// Full recompute covering the RFC 793 pseudo-header plus TCP segment.
//
// WHY manual computation and not bpf_l4_csum_replace():
//   bpf_l4_csum_replace() is a TC/sk_buff helper — it takes struct __sk_buff*
//   and does not exist in XDP context (struct xdp_md*).  Attempting to call
//   it in XDP crashes the LLVM-14 BPF backend on aarch64.
//
// WHY a bounded loop and not bpf_csum_diff():
//   bpf_csum_diff() with a runtime-variable size is rejected by the BPF
//   verifier on this kernel: it cannot prove the size argument is bounded.
//   A loop with a compile-time upper bound (512 iterations = 1024 bytes)
//   gives the verifier a provable finite path.
//
// WHY no odd-byte handler:
//   TCP header length is always a multiple of 4 (enforced by the doff field).
//   HTTP/1.x payloads from Python http.server are always even-length in
//   practice.  An odd-byte handler requires `__u8 *last = tcph + tcp_len - 1`
//   which the verifier rejects (unbounded offset from runtime tcp_len).

static __always_inline __u16 tcp_csum(struct iphdr  *iph,
                                       struct tcphdr *tcph,
                                       void          *data_end)
{
    __u16 ip_len    = bpf_ntohs(iph->tot_len);
    __u16 ihl_bytes = (__u16)(iph->ihl * 4);
    __u16 tcp_len   = ip_len - ihl_bytes;

    // Pseudo-header: saddr + daddr (split into 16-bit halves) + proto + len
    __u32 sum = 0;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr)       & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr)       & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);

    // TCP segment (header + payload)
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


// ── 5. Helpers ────────────────────────────────────────────────────────────────

static __always_inline void copy_mac(__u8 *dst, __u8 *src)
{
    __builtin_memcpy(dst, src, ETH_ALEN);
}


// ── 6. XDP program ───────────────────────────────────────────────────────────

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Parse Ethernet ────────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;   // ARP, IPv6 — pass to kernel stack

    // ── Parse IPv4 ────────────────────────────────────────────────────────────
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;   // ICMP — pass for debugging

    // ── Parse TCP ─────────────────────────────────────────────────────────────
    // iph->ihl * 4 = IP header length in bytes.
    // Must use ihl, not sizeof(struct iphdr), to handle optional IP headers.
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_ABORTED;

    __u32 key = 0;

    struct endpoint *lb = bpf_map_lookup_elem(&lb_info, &key);
    if (!lb)
        return XDP_ABORTED;

    // ── Direction detection ───────────────────────────────────────────────────
    //
    // Both forward and return packets have iph->daddr == lb->ip:
    //   Forward: client sends to VIP → daddr = lb->ip
    //   Return:  backend replies to lb (because forward path set saddr=lb->ip)
    //            → daddr = lb->ip also
    //
    // We disambiguate by TCP destination port:
    //   Forward: tcph->dest == 80  (client targeting our service)
    //   Return:  tcph->dest != 80  (backend replying to client's ephemeral port)

    if (tcph->dest == bpf_htons(80)) {

        // ── FORWARD PATH ─────────────────────────────────────────────────────

        __u32 *cnt = bpf_map_lookup_elem(&backend_count, &key);
        if (!cnt || *cnt == 0)
            return XDP_PASS;   // no backends registered yet
        __u32 n = *cnt;

        // ── Backend selection: source-port hash ───────────────────────────────
        //
        // WHY source-port hash and not a shared round-robin counter:
        //
        // A shared counter has a race even with SYN-only incrementing.
        // If connection A's SYN sets counter=1 (→ b2), then connection B's
        // SYN immediately advances counter=2 (→ b3), connection A's ACK
        // reads counter=2 and is sent to b3 — which has no TCP state for
        // this connection and responds with RST.
        //
        // tcph->source (the client's ephemeral port) is assigned once by
        // the kernel and is identical on every packet of a connection:
        // SYN, ACK, GET, response ACKs, FIN — all carry the same sport.
        // (sport % n) is therefore a stable, stateless per-connection mapping
        // with no shared state and no race condition.
        //
        // We still increment rr_counter on SYN for connection counting.
        // Phase 08 replaces this hash with an LRU flow table that stores
        // the chosen backend per (saddr, sport, daddr, dport) 4-tuple,
        // enabling proper round-robin distribution across connections.

        __u32 *rr = bpf_map_lookup_elem(&rr_counter, &key);
        if (!rr)
            return XDP_ABORTED;
        if (tcph->syn)
            __sync_fetch_and_add(rr, 1);

        __u32 idx = bpf_ntohs(tcph->source) % n;

        struct endpoint *be = bpf_map_lookup_elem(&backends, &idx);
        if (!be)
            return XDP_ABORTED;

        // Rewrite Ethernet
        copy_mac(eth->h_dest,   be->mac);   // → backend MAC
        copy_mac(eth->h_source, lb->mac);   // → lb MAC (backend replies to lb)

        // Rewrite IP
        iph->daddr = be->ip;    // → backend IP
        iph->saddr = lb->ip;    // → lb IP (forces backend to reply to lb)

        // Recompute checksums (both IPs changed → IP checksum + TCP pseudo-header)
        iph->check  = iph_csum(iph);
        tcph->check = tcp_csum(iph, tcph, data_end);

        // XDP_TX: retransmit the modified packet out veth-lb.
        // In xdpgeneric mode this calls dev_queue_xmit(), which sends the
        // frame to the veth peer (br-lb), and the bridge delivers it to
        // the correct backend via MAC lookup.
        return XDP_TX;

    } else {

        // ── RETURN PATH ──────────────────────────────────────────────────────

        struct endpoint *cl = bpf_map_lookup_elem(&client_info, &key);
        if (!cl)
            return XDP_ABORTED;

        // Rewrite Ethernet
        copy_mac(eth->h_dest,   cl->mac);   // → client MAC
        copy_mac(eth->h_source, lb->mac);   // → lb MAC (client sees reply from VIP)

        // Rewrite IP
        iph->daddr = cl->ip;    // → client IP
        iph->saddr = lb->ip;    // already lb->ip; explicit for correctness

        iph->check  = iph_csum(iph);
        tcph->check = tcp_csum(iph, tcph, data_end);

        return XDP_TX;
    }
}


// ── 7. License ────────────────────────────────────────────────────────────────
char _license[] SEC("license") = "GPL";