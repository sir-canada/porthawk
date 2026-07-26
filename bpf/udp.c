//go:build ignore

// Per-socket UDP byte counters.
//
// The kernel keeps per-socket byte counters for TCP (tcp_info, which is
// what `ss -ti` reports and what tcpstats.go reads) and keeps none at all
// for UDP. /proc/net/udp offers queue depths, not totals. So without this
// program every UDP row in the table reads zero, and a QUIC-heavy browser
// appears to move all its traffic through connections that show nothing —
// the gap only visible as the difference between the per-process capture
// number and the sum of its connection rows.
//
// Two probes, both in process context:
//   udp_sendmsg / udpv6_sendmsg  — bytes handed to the kernel to send
//   skb_consume_udp              — bytes actually delivered to the reader
// Counters are cumulative per 4-tuple, matching how /proc/net/udp
// identifies a socket, so userspace can join them onto rows it already
// has without needing to know socket inodes.
//
// kprobes, not tracepoints: the kernel exposes no stable tracepoint
// carrying UDP payload length. That means these attach points are kernel
// internals and can move across versions — the loader treats a failed
// attach as "UDP accounting unavailable" and the UI falls back to saying
// the traffic is unattributed rather than pretending it is zero.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// vmlinux.h carries kernel types, not userspace constants.
#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

// Keyed the way /proc/net/udp identifies a socket: local and remote
// address plus port. Unconnected sockets have a zero remote, exactly as
// they print in /proc, so both sides agree without special cases.
struct udp_key {
	__u8 family; // 4 or 6
	__u8 _pad[3];
	__u32 saddr[4]; // v4 in word 0, network byte order
	__u32 daddr[4];
	__u16 sport; // host byte order, like /proc/net/udp
	__u16 dport;
};

struct udp_val {
	__u64 tx;
	__u64 rx;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct udp_key);
	__type(value, struct udp_val);
} udp_bytes SEC(".maps");

// fill keys a socket the same way for both directions. Returns 0 on
// success; a socket we cannot read is simply not counted.
static __always_inline int fill(struct udp_key *k, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	__builtin_memset(k, 0, sizeof(*k));
	if (family == AF_INET) {
		k->family = 4;
		k->saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		k->daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		k->family = 6;
		BPF_CORE_READ_INTO(&k->saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&k->daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	} else {
		return -1;
	}
	// skc_num is already host order, skc_dport is not.
	k->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	k->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	return 0;
}

static __always_inline void add(struct sock *sk, __u64 tx, __u64 rx)
{
	struct udp_key k;
	struct udp_val zero = {}, *v;

	if (!sk || fill(&k, sk))
		return;
	v = bpf_map_lookup_elem(&udp_bytes, &k);
	if (!v) {
		bpf_map_update_elem(&udp_bytes, &k, &zero, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&udp_bytes, &k);
		if (!v)
			return;
	}
	// Per-socket counters, and a socket's send path is serialised by its
	// own lock, but the same socket can send on one CPU while receiving
	// on another — so each direction still gets an atomic add.
	if (tx)
		__sync_fetch_and_add(&v->tx, tx);
	if (rx)
		__sync_fetch_and_add(&v->rx, rx);
}

// len here is what the caller asked to send. The wire cost is higher (UDP
// and IP headers), which is deliberate: these numbers are meant to line up
// with the TCP rows, which are also payload-only.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
	add(sk, len, 0);
	return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(udpv6_send, struct sock *sk, struct msghdr *msg, size_t len)
{
	add(sk, len, 0);
	return 0;
}

// skb_consume_udp fires once the payload is handed to the reader, so it
// counts what the process actually got — not what arrived and was dropped
// for a full receive buffer. Both v4 and v6 come through here.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(udp_consume, struct sock *sk, struct sk_buff *skb, int len)
{
	if (len > 0)
		add(sk, 0, len);
	return 0;
}
