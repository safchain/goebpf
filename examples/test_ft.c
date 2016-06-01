#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>

#include "../libbpf.h"
#include "test_ft.h"

struct bpf_map_def MAP("flow_table") flow_table = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key),
	.value_size = sizeof(struct flow),
	.max_entries = 256,
};

static void fill_transport_tcp(struct __sk_buff *skb, int offset,
	struct flow_key *key)
{
	struct transport_layer *layer = &key->transport_layer;

	layer->port_src = load_half(skb, offset + offsetof(struct tcphdr, source));
	layer->port_dst = load_half(skb, offset + offsetof(struct tcphdr, source));
}

static void fill_transport_tcp_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	/* TODO */
}

static void fill_transport_udp(struct __sk_buff *skb, int offset,
	struct flow_key *key)
{
	struct transport_layer *layer = &key->transport_layer;

	layer->port_src = load_half(skb, offset + offsetof(struct udphdr, source));
	layer->port_dst = load_half(skb, offset + offsetof(struct udphdr, source));
}

static void fill_transport_udp_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	/* TODO */
}

static void fill_network(struct __sk_buff *skb, int offset,
	struct flow_key *key)
{
	struct network_layer *layer = &key->network_layer;

	layer->ip_src = load_word(skb, offset + offsetof(struct iphdr, saddr));
	layer->ip_dst = load_word(skb, offset + offsetof(struct iphdr, daddr));

	__u32 proto = load_byte(skb, offset + offsetof(struct iphdr, protocol));

	__u8 verlen = load_byte(skb, offset);
	offset += (verlen & 0xF) << 2;

	switch (proto) {
		case IPPROTO_TCP:
			fill_transport_tcp(skb, offset, key);
		case IPPROTO_UDP:
			fill_transport_udp(skb, offset, key);
	}
}

static void fill_network_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	/* TODO */

	__u32 proto = load_byte(skb, offset + offsetof(struct iphdr, protocol));

	__u8 verlen = load_byte(skb, offset);
	offset += (verlen & 0xF) << 2;

	switch (proto) {
		case IPPROTO_TCP:
			fill_transport_tcp_stats(skb, offset, stats);
		case IPPROTO_UDP:
			fill_transport_udp_stats(skb, offset, stats);
	}
}

static __always_inline void _fill_haddr(struct __sk_buff *skb, int offset,
	unsigned char *mac)
{
	mac[0] = load_byte(skb, offset);
	mac[1] = load_byte(skb, offset + 1);
	mac[2] = load_byte(skb, offset + 2);
	mac[3] = load_byte(skb, offset + 3);
	mac[4] = load_byte(skb, offset + 4);
	mac[5] = load_byte(skb, offset + 5);
}

static void fill_link(struct __sk_buff *skb, int offset, struct flow_key *key)
{
	struct link_layer *layer = &key->link_layer;

	_fill_haddr(skb, offset + offsetof(struct ethhdr, h_source), layer->mac_src);
	_fill_haddr(skb, offset + offsetof(struct ethhdr, h_dest), layer->mac_dst);
}

static void fill_link_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	__sync_fetch_and_add(&stats->link_layer.packets, 1);
	__sync_fetch_and_add(&stats->link_layer.bytes, skb->len);
}

static void fill_stats(struct __sk_buff *skb, struct flow_stats *stats)
{
	fill_link_stats(skb, 0, stats);

	__u32 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
	switch (proto) {
	case ETH_P_IP:
		fill_network_stats(skb, ETH_HLEN, stats);
	}
}

static void fill_key(struct __sk_buff *skb, struct flow_key *key)
{
	fill_link(skb, 0, key);

	__u32 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
	switch (proto) {
	case ETH_P_IP:
		fill_network(skb, ETH_HLEN, key);
	}
}

static void fill_flow(struct __sk_buff *skb, struct flow *flow)
{
	fill_key(skb, &flow->key);
	fill_stats(skb, &flow->stats);

	flow->first = bpf_ktime_get_ns();
	flow->last = bpf_ktime_get_ns();
}

SOCKET("test")
int bpf_test(struct __sk_buff *skb)
{
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	__u64 tm = bpf_ktime_get_ns();

	struct flow flow = {}, *prev;
	fill_key(skb, &flow.key);

	prev = bpf_map_lookup_element(&flow_table, &flow.key);
	if (prev) {
		fill_stats(skb, &prev->stats);
		prev->first = tm;
	} else {
		fill_stats(skb, &flow.stats);
		flow.first = tm;

		bpf_map_update_element(&flow_table, &flow.key, &flow, BPF_ANY);
	}

	return 0;
}
char _license[] LICENSE = "GPL";
