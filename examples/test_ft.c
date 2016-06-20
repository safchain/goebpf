#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/bpf.h>

#include "../libbpf.h"
#include "test_ft.h"

MAP(flow_table) {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key),
	.value_size = sizeof(struct flow),
	.max_entries = 256,
};

static void fill_transport(struct __sk_buff *skb, __u8 protocol, int offset,
	struct flow_key *key)
{
	struct transport_layer *layer = &key->transport_layer;

	layer->protocol = protocol;
	layer->port_src = load_half(skb, offset);
	layer->port_dst = load_half(skb, offset + sizeof(__be16));
}

static void update_transport_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	__sync_fetch_and_add(&stats->transport_layer.packets, 1);
	__sync_fetch_and_add(&stats->transport_layer.bytes, skb->len - offset);
}

static void fill_network(struct __sk_buff *skb, int offset,
	struct flow_key *key)
{
	struct network_layer *layer = &key->network_layer;

	layer->ip_src = load_word(skb, offset + offsetof(struct iphdr, saddr));
	layer->ip_dst = load_word(skb, offset + offsetof(struct iphdr, daddr));

	__u8 protocol = load_byte(skb, offset + offsetof(struct iphdr, protocol));

	__u8 verlen = load_byte(skb, offset);
	offset += (verlen & 0xF) << 2;

	switch (protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
			fill_transport(skb, protocol, offset, key);
	}
}

static void update_network_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	__sync_fetch_and_add(&stats->network_layer.packets, 1);
	__sync_fetch_and_add(&stats->network_layer.bytes, skb->len - offset);

	__u32 proto = load_byte(skb, offset + offsetof(struct iphdr, protocol));

	__u8 verlen = load_byte(skb, offset);
	offset += (verlen & 0xF) << 2;

	switch (proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
			update_transport_stats(skb, offset, stats);
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

static void update_link_stats(struct __sk_buff *skb, int offset,
	struct flow_stats *stats)
{
	__sync_fetch_and_add(&stats->link_layer.packets, 1);
	__sync_fetch_and_add(&stats->link_layer.bytes, skb->len);
}

static void update_stats(struct __sk_buff *skb, struct flow_stats *stats)
{
	update_link_stats(skb, 0, stats);

	__u32 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
	switch (proto) {
	case ETH_P_IP:
		update_network_stats(skb, ETH_HLEN, stats);
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

SOCKET(test)
int bpf_test(struct __sk_buff *skb)
{
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	__u64 tm = bpf_ktime_get_ns();

	struct flow flow = {}, *prev;
	fill_key(skb, &flow.key);

	prev = bpf_map_lookup_element(&flow_table, &flow.key);
	if (prev) {
		update_stats(skb, &prev->stats);
		prev->last = tm;
	} else {
		update_stats(skb, &flow.stats);
		flow.start = tm;
		flow.last = tm;

		bpf_map_update_element(&flow_table, &flow.key, &flow, BPF_ANY);
	}

	return 0;
}
char _license[] LICENSE = "GPL";
