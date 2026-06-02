// Attaches to the veth interface inside the "lb" network namespace.
// Inspects every arriving Ethernet frame and prints a one-line trace
// for TCP packets destined to port 80.  Returns XDP_PASS for everything
// so the kernel networking stack processes the packet normally afterward.
//
// ── 1. Kernel headers ────────────────────────────────────────────────────────
//
// We include only what we actually use.  Each header pulls in the kernel's
// definition of the corresponding data structure:
//
//   linux/bpf.h        — XDP context (xdp_md), BPF helper prototypes,
//                        map type constants
//   linux/if_ether.h   — struct ethhdr  (14-byte Ethernet header)
//   linux/ip.h         — struct iphdr   (20-byte IPv4 header, variable with opts)
//   linux/tcp.h        — struct tcphdr  (20-byte TCP header, variable with opts)
//   linux/in.h         — IPPROTO_TCP, ETH_P_IP constants
//   bpf/bpf_helpers.h  — bpf_printk(), SEC() macro
//   bpf/bpf_endian.h   — bpf_ntohs(), bpf_htons()
//


#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// ── 2. The XDP program entry point ──────────────────────────────────────────
//
// SEC("xdp") tells the ELF linker to place this function in a section named
// "xdp".  When bpftool or ip-link loads the object file, it looks for a
// section matching the program type, "xdp" for XDP programs.
//
// Why SEC() at all?  The BPF loader finds programs by ELF section name,
// not by C symbol name.  Without it the function compiles fine but the
// loader cannot locate it.
//
// The function signature is fixed by the kernel ABI:
//   int fn(struct xdp_md *ctx)
// ctx carries two fields we use: ctx->data (start of the packet) and
// ctx->data_end (one byte past the end).  Everything between them is
// the raw Ethernet frame in memory.

SEC("xdp")
int xdp_observer(struct xdp_md *ctx)
{
    // ── 3. Packet data pointers ──────────────────────────────────────────────
    //
    // ctx->data and ctx->data_end are __u32 offsets stored as integers.
    // We cast them to void* to do pointer arithmetic.
    //


    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;


    // ── 4. Ethernet header parse + bounds check ──────────────────────────────
    //
    // We treat the start of the packet as a struct ethhdr.
    // Before reading ANY field of eth we must prove to the BPF verifier
    // that [data, data + sizeof(ethhdr)] lies entirely within the packet.
    //

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;


    // ── 5. EtherType filter ──────────────────────────────────────────────────
    //
    // h_proto is a big-endian (network byte order) 16-bit field.
    // The CPU on x86/ARM is little-endian.  We use bpf_htons() to convert
    // the constant ETH_P_IP (0x0800) from host byte order to network byte
    // order before comparing.


    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;


    // ── 6. IPv4 header parse + bounds check ─────────────────────────────────
    //
    // The IPv4 header starts immediately after the 14-byte Ethernet header.
    // We compute its address by adding sizeof(struct ethhdr) to data, not
    // by using eth+1 — both are equivalent but explicit pointer arithmetic
    // makes the offset visible.
    //
    // iph->ihl is the "IP header length" field in 32-bit words.
    // A minimal IPv4 header is 20 bytes (ihl=5).  Options can extend it to
    // 60 bytes.  In this phase we don't use ihl for offset calculation yet
    // (that matters when we need to find the TCP header in phase 07), but we
    // still bounds-check the minimal 20-byte fixed portion.

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;


    // ── 7. Protocol filter ───────────────────────────────────────────────────
    //
    // iph->protocol is a single byte — no byte-swap needed.
    // IPPROTO_TCP is defined in linux/in.h as 6.
    // We pass non-TCP (UDP, ICMP, etc.) without inspection.

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;


    // ── 8. TCP header parse + bounds check ──────────────────────────────────
    //
    // The TCP header starts after the IPv4 header.  iph->ihl gives the IP
    // header length in 32-bit (4-byte) words, so the actual byte length is
    // iph->ihl * 4.  We must use this — not sizeof(struct iphdr) — because
    // IP options are real and a fixed 20-byte offset would point into garbage
    // if any are present.
    //
    // Why cast iph to (void *) before the arithmetic?
    // iph is struct iphdr*.  Adding an integer to a typed pointer scales by
    // sizeof(struct iphdr) = 20.  We want to add *bytes*, not structs.
    // Casting to void* (or char*) makes the arithmetic byte-accurate.

    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_ABORTED;


    // ── 9. Port filter ───────────────────────────────────────────────────────
    //
    // We only trace packets directed at our VIP port (80).
    // tcph->dest is big-endian; bpf_htons(80) converts the constant.
    //
    // In a real observer you might trace all ports, but filtering here
    // keeps the trace output focused during learning.

    if (tcph->dest != bpf_htons(80))
        return XDP_PASS;


    // ── 10. Trace output ─────────────────────────────────────────────────────
    //
    // bpf_printk() writes to the kernel trace ring buffer:
    //   /sys/kernel/debug/tracing/trace_pipe

    bpf_printk("XDP_OBS: src=%pI4 dst=%pI4 dport=80\n",
               &iph->saddr, &iph->daddr);


    // ── 11. Return XDP_PASS ──────────────────────────────────────────────────
    //
    // XDP_PASS hands the packet to the kernel networking stack unchanged.

    return XDP_PASS;
}


// ── 12. License string ───────────────────────────────────────────────────────
//
// The kernel requires a GPL-compatible license for programs that call GPL-only
// BPF helpers (which bpf_printk is).  Without this the verifier rejects
// the program with "unknown func bpf_trace_printk".
// The string must be in a section named "license".

char _license[] SEC("license") = "GPL";