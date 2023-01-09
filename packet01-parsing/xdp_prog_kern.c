/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"


#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK		0x0fff

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_valn_encapsulated_proto;
};

struct collect_vlans
{
	__u16 id[VLAN_MAX_DEPTH];
};


static __always_inline int proto_is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}


/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr,
					struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	__u16 h_proto;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	struct vlan_hdr *vln = nh->pos;
	h_proto = eth->h_proto;

	int i;
	#pragma unroll
	for(i=0; i<VLAN_MAX_DEPTH; i++) {
		if(!proto_is_vlan(h_proto)) {
			break;
		}
		if(vln + 1 > data_end) {
			break;
		}
		h_proto = vln->h_valn_encapsulated_proto;
		if(vlans)
			vlans->id[i] = (bpf_ntohs(vln->h_vlan_TCI) & VLAN_VID_MASK);
		
		vln++;
	}
	
	nh->pos = vln;
	return h_proto;
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if(ip6h + 1 > data_end) {
		return -1;
	}

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
										void *data_end,
										struct iphdr **ip4hdr)
{
	struct iphdr *ip4h = nh->pos;
	if(ip4h + 1 > data_end) {
		return -1;
	}

	int hdrsize = ip4h->ihl*4;
	if(hdrsize < sizeof(*ip4h)) {
		return -1;
	}

	if(nh->pos + hdrsize > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ip4hdr = ip4h;
	return ip4h->protocol;
}


/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if(icmp6h + 1 > data_end) {
		return -1;
	}

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return bpf_ntohs(icmp6h->icmp6_sequence);
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
							void *data_end,
							struct icmphdr **icmp4hdr)
{
	struct icmphdr *icmp4h = nh->pos;
	if(icmp4h + 1 > data_end) {
		return -1;
	}

	nh->pos = icmp4h + 1;
	*icmp4hdr = icmp4h;

	return bpf_ntohs(icmp4h->un.echo.sequence);
}

static struct iphdr_parser
{
	int (*ip4_parser)(struct hdr_cursor*, void*, struct iphdr**);
	int (*ip6_parser)(struct hdr_cursor*, void*, struct ipv6hdr**);
} Default_iphdr_parser = {&parse_ip4hdr, &parse_ip6hdr};

static struct icmp_parser
{
	int (*icmp4_parser)(struct hdr_cursor*, void*, struct icmphdr**);
	int (*icmp6_parser)(struct hdr_cursor*, void*, struct icmp6hdr**);
} Default_icmp_parser = {&parse_icmp4hdr, &parse_icmp6hdr};

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct collect_vlans *vlans = {0};
	

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth, vlans);

	int ip_type;
	struct iphdr *ip4hdr;
	struct ipv6hdr *ip6hdr;
	switch (nh_type)
	{
	case bpf_htons(ETH_P_IP):
		ip_type = Default_iphdr_parser.ip4_parser(&nh, data_end, &ip4hdr);
		break;
	
	case bpf_htons(ETH_P_IPV6):
		ip_type = Default_iphdr_parser.ip6_parser(&nh, data_end, &ip6hdr);
		break;
	default:
		goto out;
		break;
	}

	// if(!(nh_type == bpf_htons(ETH_P_IP) ||(nh_type == bpf_htons(ETH_P_IPV6) || proto_is_vlan(nh_type)))) {
	// 	goto out;
	// }
	// struct ipv6hdr *ip6hdr;
	// int ip_type = parse_ip6hdr(&nh, data_end, &ip6hdr);

	// if(!(ip_type != IPPROTO_ICMP || ip_type != IPPROTO_ICMPV6))
	// 	goto out;

	int sequence;
	struct icmphdr *icmp4hdr;
	struct icmp6hdr *icmp6hdr;
	switch (ip_type)
	{
	case IPPROTO_ICMP:
		sequence = Default_icmp_parser.icmp4_parser(&nh, data_end, &icmp4hdr);
		break;
	case IPPROTO_ICMPV6:
		sequence = Default_icmp_parser.icmp6_parser(&nh, data_end, &icmp6hdr);
		break;
	default:
		goto out;
		break;
	}

	// struct icmp6hdr *icmp6hdr;
	// int sequence = parse_icmp6hdr(&nh, data_end, &icmp6hdr);

	if(sequence % 2 == 1)
		goto out;
		
	action = XDP_DROP;

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
