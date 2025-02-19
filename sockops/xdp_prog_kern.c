/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

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
	__u32 *is_lbip = bpf_map_lookup_elem(&lb_ips_map, &iphdr->saddr);
	if(!is_lbip) {
		return XDP_PASS;
	}
	__u32 key = DEFAULT_KEY_OR_VALUE;
	// __u64 start = bpf_ktime_get_ns();
	struct connection *flows = bpf_map_lookup_elem(&existed_counter_map, &key);
	// __u64 end = bpf_ktime_get_ns();
	// printk("Lookup time: %llu\n", end-start);

	char v = DEFAULT_KEY_OR_VALUE;
	// Not found an initial entry, create one...
	if(!flows) {
		struct connection initial_flow;
		initial_flow.count = 0;char v = DEFAULT_KEY_OR_VALUE;
		if(bpf_map_update_elem(&existed_counter_map, &initial_flow, &v, BPF_NOEXIST) < 0)
			printk("XDP: Not found the existed connection map, and initialize error!\n");
		return XDP_DROP;
	}

	// Allow tcp fin flag pass, avoid wierd connection state
	if(tcphdr->fin == 1) {
		printk("XDP: Let TCP fin packet pass\n");
		return XDP_PASS;
	}
	if(tcphdr->rst == 1) {
		if(bpf_map_delete_elem(&reservation_ops_map, reservation) >= 0) {
			(void) __sync_add_and_fetch(&flows->count, -1);
		}
		return XDP_PASS;
	}

	reservation->client_ip4 = iphdr->saddr;
	reservation->client_port = tcphdr->source;
	char *high_pressure_lock_down = bpf_map_lookup_elem(&psi_map, &v);

	if((high_pressure_lock_down && *high_pressure_lock_down == 1) || flows->count >= MAX_CONN) {
		struct flow_key *first_item = bpf_map_lookup_elem(&reservation_ops_map, reservation);
		if(first_item) {
			return XDP_PASS;
		}
		if((high_pressure_lock_down && *high_pressure_lock_down == 1)) {
			printk("Lock door due to high pressure, current count: %d\n", flows->count);
		}
//		printk("NIC: Existed flows are saturated, and not found current flow in map\n");
		return XDP_DROP;
	}

	// packet with tcp syn flag
	 if(ENABLE_THROTTLE_SYN == 1 && (tcphdr->syn == 1 && tcphdr->ack == 0)) {
		struct burst_per_open *burst_count = bpf_map_lookup_elem(&burst_connection_map, &key);
		if(!burst_count) {
			struct burst_per_open initial_burst;
			initial_burst.count = 1;
			initial_burst.last_updated = getBootTimeSec();
			if(bpf_map_update_elem(&burst_connection_map, &key, &initial_burst, BPF_NOEXIST) < 0)
				return XDP_DROP;
			return XDP_PASS;
		}
		

		if(burst_count->count > BURST_COUNT) {
			// NanoSec to Sec
			__u32 cur_time = getBootTimeSec();
		//	printk("Diff: %d\n", cur_time - burst_count->last_updated);
			// Gate not open
			if((cur_time - burst_count->last_updated) < GATE_OPEN_INTERVAL) {
				return XDP_DROP;
			}
		//	printk("Gate open %d %d!!\n", (cur_time - burst_count->last_updated), GATE_OPEN_INTERVAL);
			(void) __sync_add_and_fetch(&burst_count->count, -(burst_count->count));
		}

		
		(void) __sync_add_and_fetch(&burst_count->count, 1);
		if(burst_count->count > BURST_COUNT) {
			printk("Over burst count %d\n", BURST_COUNT);
			return XDP_DROP;
		}
		// For Safety, use atomic operation
		(void) __sync_add_and_fetch(&burst_count->last_updated, getBootTimeSec() - burst_count->last_updated);
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
//		printk("Current CPU: %lu\n", bpf_get_smp_processor_id());
		return xdp_stats_record_action(iphdr, tcphdr, &reservation);
	}

out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
