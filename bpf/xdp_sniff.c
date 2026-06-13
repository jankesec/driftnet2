// driftnet2 eBPF XDP Packet Sniffer
// Compile: clang -O2 -target bpf -c xdp_sniff.c -o xdp_sniff.o
// Requires: Linux kernel 5.8+ with CONFIG_XDP_SOCKETS=y

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;   // 6=TCP, 17=UDP
    __u8  flags;      // TCP flags (SYN, ACK, PSH, etc.)
    __u16 payload_len;
    __u8  data[MAX_PACKET_SIZE - 20];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer
} packets SEC(".maps");

static __always_inline int is_target_port(__u16 port) {
    return port == TARGET_PORT_HTTP    || port == TARGET_PORT_HTTPS  ||
           port == TARGET_PORT_DNS     || port == TARGET_PORT_SMB    ||
           port == TARGET_PORT_LDAP    || port == TARGET_PORT_FTP    ||
           port == TARGET_PORT_TELNET  || port == TARGET_PORT_SMTP   ||
           port == TARGET_PORT_POP3    || port == TARGET_PORT_IMAP   ||
           port == TARGET_PORT_SMTP_S;
}

static __always_inline __u16 parse_tcp_flags(struct tcphdr *tcp) {
    __u16 flags = 0;
    if (tcp->syn) flags |= 0x02;
    if (tcp->ack) flags |= 0x10;
    if (tcp->psh) flags |= 0x08;
    if (tcp->fin) flags |= 0x01;
    if (tcp->rst) flags |= 0x04;
    return flags;
}

SEC("xdp")
int xdp_sniff(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = ip->protocol;
    __u8 tcp_flags = 0;
    void *transport_hdr = (void *)ip + ip_hdr_len;
    int payload_offset = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_hdr;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        src_port = __bpf_ntohs(tcp->source);
        dst_port = __bpf_ntohs(tcp->dest);
        tcp_flags = parse_tcp_flags(tcp);

        payload_offset = ip_hdr_len + (tcp->doff * 4);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_hdr;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        src_port = __bpf_ntohs(udp->source);
        dst_port = __bpf_ntohs(udp->dest);
        payload_offset = ip_hdr_len + sizeof(struct udphdr);
    } else {
        return XDP_PASS;
    }

    if (!is_target_port(src_port) && !is_target_port(dst_port))
        return XDP_PASS;

    struct packet_event *evt = bpf_ringbuf_reserve(&packets, sizeof(struct packet_event), 0);
    if (!evt)
        return XDP_PASS;

    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->protocol = protocol;
    evt->flags = tcp_flags;

    int total_len = __bpf_ntohs(ip->tot_len);
    int payload_len = total_len - payload_offset;
    if (payload_len < 0)
        payload_len = 0;
    if (payload_len > (int)sizeof(evt->data))
        payload_len = sizeof(evt->data);
    evt->payload_len = (__u16)payload_len;

    if (payload_len > 0) {
        void *payload_start = data + payload_offset;
        if (payload_start + payload_len <= data_end) {
            __builtin_memcpy(evt->data, payload_start, payload_len);
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
