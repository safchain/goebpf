#ifndef __TEST_FT_H
#define __TEST_FT_H

#include <linux/if_ether.h>
#include <linux/bpf.h>

struct layer_stats {
	__u64 packets;
	__u64 bytes;
};

struct link_layer {
	unsigned char mac_src[ETH_ALEN];
	unsigned char mac_dst[ETH_ALEN];
};

struct network_layer {
	__be32 ip_src;
	__be32 ip_dst;
};

struct transport_layer {
	__u8   protocol;
	__be16 port_src;
	__be16 port_dst;
};

struct flow_key {
	struct link_layer      link_layer;
	struct network_layer   network_layer;
	struct transport_layer transport_layer;
};

struct flow_stats {
	struct layer_stats link_layer;
	struct layer_stats network_layer;
	struct layer_stats transport_layer;
};

struct flow {
	struct flow_key   key;
	struct flow_stats stats;

	__u64             start;
	__u64             last;
};

#endif
