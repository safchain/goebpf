#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/bpf.h>

#include "../libbpf.h"

struct bpf_map_def MAP("first") my_map1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(long),
	.max_entries = 256,
};

struct bpf_map_def MAP("second") my_map2 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 4,
	.value_size = sizeof(long),
	.max_entries = 256,
};

SOCKET("test")
int bpf_test(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	char key[4] = "abc";
	long *value1, *value2;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value1 = bpf_map_lookup_element(&my_map1, &index);
  if (value1)
		__sync_fetch_and_add(value1, skb->len);

	value2 = bpf_map_lookup_element(&my_map2, key);
	if (value2)
		__sync_fetch_and_add(value2, 10000);
	else {
		long v = 999;
		bpf_map_update_element(&my_map2, key, &v, BPF_ANY);
	}

	return 0;
}
char _license[] LICENSE = "GPL";
