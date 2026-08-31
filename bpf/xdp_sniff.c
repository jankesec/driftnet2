// driftnet2 eBPF XDP Packet Sniffer (IPv4 + IPv6)
// Compile: clang -O2 -target bpf -c xdp_sniff.c -o xdp_sniff.o
// Requires: Linux kernel 5.8+ with CONFIG_XDP_SOCKETS=y

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_SIZE 1500

#define TARGET_PORT_HTTP    80
#define TARGET_PORT_HTTPS   443
#define TARGET_PORT_DNS     53
#define TARGET_PORT_SMB     445
#define TARGET_PORT_LDAP    389
#define TARGET_PORT_FTP     21
#define TARGET_PORT_TELNET  23
#define TARGET_PORT_SMTP    25
#define TARGET_PORT_POP3    110
#define TARGET_PORT_IMAP    143
#define TARGET_PORT_SMTP_S  587

struct packet_event {
    __u8  src_ip[16];   // IPv6 or IPv4 (stored in last 4 bytes, rest zeroed)
    __u8  dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;     // 6=TCP, 17=UDP
    __u8  flags;        // TCP flags
    __u16 payload_len;
    __u8  data[MAX_PACKET_SIZE - 42];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} packets SEC(".maps");

static __always_inline int is_target_port(__u16 port) {
    return port == TARGET_PORT_HTTP    || port == TARGET_PORT_HTTPS  ||
           port == TARGET_PORT_DNS     || port == TARGET_PORT_SMB    ||
           port == TARGET_PORT_LDAP    || port == TARGET_PORT_FTP    ||
           port == TARGET_PORT_TELNET  || port == TARGET_PORT_SMTP   ||
           port == TARGET_PORT_POP3    || port == TARGET_PORT_IMAP   ||
           port == TARGET_PORT_SMTP_S;
}

static __always_inline __u8 parse_tcp_flags(struct tcphdr *tcp) {
    __u8 flags = 0;
    if (tcp->syn) flags |= 0x02;
    if (tcp->ack)  flags |= 0x10;
    if (tcp->psh)  flags |= 0x08;
    if (tcp->fin)  flags |= 0x01;
    if (tcp->rst)  flags |= 0x04;
    return flags;
}

static __always_inline void store_ipv4(__u8 *dst, __be32 addr) {
    __builtin_memset(dst, 0, 12);
    __builtin_memcpy(dst + 12, &addr, 4);
}

static __always_inline void store_ipv6(__u8 *dst, const struct in6_addr *addr) {
    __builtin_memcpy(dst, addr->in6_u.u6_addr8, 16);
}

static __always_inline int handle_transport(struct packet_event *evt, void *transport_hdr, void *data_end,
                                             __u8 protocol, int ip_hdr_len) {
    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0;
    int payload_offset = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_hdr;
        if ((void *)(tcp + 1) > data_end)
            return -1;

        src_port = __bpf_ntohs(tcp->source);
        dst_port = __bpf_ntohs(tcp->dest);
        tcp_flags = parse_tcp_flags(tcp);
        payload_offset = ip_hdr_len + (tcp->doff * 4);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_hdr;
        if ((void *)(udp + 1) > data_end)
            return -1;

        src_port = __bpf_ntohs(udp->source);
        dst_port = __bpf_ntohs(udp->dest);
        payload_offset = ip_hdr_len + sizeof(struct udphdr);
    } else {
        return -1;
    }

    if (!is_target_port(src_port) && !is_target_port(dst_port))
        return -1;

    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->protocol = protocol;
    evt->flags = tcp_flags;

    int payload_len = (int)((long)data_end - ((long)transport_hdr + payload_offset - ip_hdr_len));
    payload_len = payload_len - (payload_offset - ip_hdr_len);
    if (payload_len < 0)
        payload_len = 0;
    if (payload_len > (int)sizeof(evt->data))
        payload_len = sizeof(evt->data);
    evt->payload_len = (__u16)payload_len;

    if (payload_len > 0) {
        void *payload_start = (void *)((long)transport_hdr + (payload_offset - ip_hdr_len));
        if (payload_start + payload_len <= data_end) {
            __builtin_memcpy(evt->data, payload_start, payload_len);
        }
    }

    return 0;
}

SEC("xdp")
int xdp_sniff(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u16 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr))
            return XDP_PASS;

        void *transport_hdr = (void *)ip + ip_hdr_len;

        struct packet_event *evt = bpf_ringbuf_reserve(&packets, sizeof(struct packet_event), 0);
        if (!evt)
            return XDP_PASS;

        store_ipv4(evt->src_ip, ip->saddr);
        store_ipv4(evt->dst_ip, ip->daddr);

        int total_len = __bpf_ntohs(ip->tot_len);
        if (total_len < ip_hdr_len)
            return XDP_PASS;

        if (handle_transport(evt, transport_hdr, data_end, ip->protocol, ip_hdr_len) != 0) {
            bpf_ringbuf_discard(evt, 0);
            return XDP_PASS;
        }

        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;
    }

    if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        void *transport_hdr = (void *)(ip6 + 1);
        __u8 nexthdr = ip6->nexthdr;

        struct packet_event *evt = bpf_ringbuf_reserve(&packets, sizeof(struct packet_event), 0);
        if (!evt)
            return XDP_PASS;

        store_ipv6(evt->src_ip, &ip6->saddr);
        store_ipv6(evt->dst_ip, &ip6->daddr);

        if (handle_transport(evt, transport_hdr, data_end, nexthdr, sizeof(struct ipv6hdr)) != 0) {
            bpf_ringbuf_discard(evt, 0);
            return XDP_PASS;
        }

        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
