/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}

// static __always_inline void print_ip(unsigned int ip)
// {
//     unsigned char bytes[4];
//     bytes[0] = ip & 0xFF;
//     bytes[1] = (ip >> 8) & 0xFF;
//     bytes[2] = (ip >> 16) & 0xFF;
//     bytes[3] = (ip >> 24) & 0xFF;   

// 	printk("%d.%d.%d\n", bytes[1], bytes[2], bytes[3]);
// }

static __always_inline
int xdp_stats_record_action(struct iphdr *iphdr, struct tcphdr *tcphdr, struct flow_key *reservation)
{
	reservation->server_ip4 = iphdr->daddr;
	reservation->server_port = tcphdr->dest;
	reservation->client_ip4 = iphdr->saddr;
	reservation->client_port = tcphdr->source;
	

	__u32 key = 0;
	struct connection *flows = bpf_map_lookup_elem(&existed_connection_map, &key);
	if(!flows) {
		printk("Socket: Not found the existed connection map\n");
		return XDP_PASS;
	}
	
	if(flows->count >= MAX_CONN) {
		struct flow_key *first_item = bpf_map_lookup_elem(&reservation_ops_map, reservation);
		if(first_item) {
			printk("NIC: Existed connection, let go!!!!\n");
			return XDP_PASS;
		}
		printk("NIC: Existed flows are saturated, and not found current flow in map\n");
		return XDP_DROP;
	}
		
	printk("current flow is acceptable, current count: %d\n", flows->count);


	return XDP_PASS;
}

SEC("xdp_pass")
int  xdp_pass_func(struct xdp_md *ctx)
{
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			goto out;
		}
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			goto out;
		}
		if(tcphdr->dest != bpf_htons(SWIFT_PROXY_SERVER_PORT)) {
			goto out;
		}
		struct flow_key reservation = {};
		return xdp_stats_record_action(iphdr, tcphdr, &reservation);
	}

out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
