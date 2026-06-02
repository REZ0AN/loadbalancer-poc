# Load Balancer PoC

A hands-on exploration of how Linux load balancers work under the hood, building from scratch using network namespaces, veth pairs, and bridges to understand the mechanics before reaching for production tools.

## Goals

- Understand L4/L7 load balancing from first principles
- Explore the kernel primitives that make it possible (netns, veth, bridge, iptables, IPVS, eBPF/XDP)
- Build progressively, from a static topology to programmable data planes

## Repository Layout

```
loadbalancer-poc/
├── network-namespaces-mental-model/    # Bridge + netns + veth topology
├── iptables-dnat-simplest-lb/          # iptables + DNAT [simplest loadbalancer]
├── ipvs-builtin-linux-lb/              # IPVS NAT mode, scheduling, per-backend stats
├── nftables-dnat-lb/                   # nftables maps, jhash, DNAT, stateless stickiness
├── xdp-observer/                       # XDP hook, Traffic Trace before packet reach to network stack
├── images/                             # Reference Images
└── docs/                               # Phase wise Docs
```

## Phases 

| # | Phase | What you'll learn |
|---|---|---|
| 01 | [Network Namespaces Mental Model](./docs/ns-mental-model.md) | Network namespaces, veth pairs, Linux bridges |
| 02 | [iptables DNAT — Simplest LoadBalancer](./docs/iptables-dnat-simplest-lb.md) | iptables DNAT, statistic module, MASQUERADE, conntrack |
| 03 | [IPVS — Built-in Linux L4 LoadBalancer](./docs/ipvs-builtin-linux-lb.md) | IPVS NAT mode, scheduling algorithms, source hashing, per-backend stats |
| 04 | [nftables — DNAT LoadBalancer with jhash](./docs/nftables-dnat-lb.md) | nftables maps, jhash flow hashing, concat DNAT, stateless stickiness |
| 05 | [XDP Observer](./docs/xdp-observer.md) | eBPF/XDP programs, BPF verifier, XDP return codes, kernel tracing via trace_pipe |

## Prerequisites

- Linux host (or VM — Lima/UTM/Multipass all fine)
- Root access (`sudo`)
- Generic `python3`, `curl`, `clang`, `llvm`, `libelf-dev`, `libbpf-dev`, `libpcap-dev`, `build-essential`, `linux-tools-common`, `linux-headers-generic`, `linux-tools-generic`, `iproute2` `iputils-ping`, `dwarves`, `tcpdump`, `bind9-dnsutils`, `iptables`, `ipvsadm`, `nftables`, `conntrack`
- Kernel Specific `linux-headers-$(uname -r)`, `linux-tools-$(uname -r)` 

## Quick Start

```bash
# Clone and enter
git clone <repo-url>
cd loadbalancer-poc
```
Phase by Phase follow the guidelines.

## References

- [Linux Network Namespaces — man page](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [iximiuz Labs — Container Networking](https://labs.iximiuz.com/tutorials)
- [Cilium docs on eBPF/XDP](https://docs.cilium.io/)
- [xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
