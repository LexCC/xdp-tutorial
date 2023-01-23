
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

#define SK_DROP 0
#define SK_PASS 1

static inline
void extract_key4_from_skb(unsigned int client_ip, unsigned short client_port, struct flow_key *flow)
{
	flow->client_ip4 = client_ip;
	flow->client_port = client_port;
}

/*
 * Insert socket into existed connection map
 */
// -1 should drop, 0 can pass
static inline
int bpf_sock_ipv4(struct flow_key *flow)
{ 
    int ret = -1;
    __u32 key = DEFAULT_KEY_OR_VALUE;
    struct connection *curr_connection;
    
	struct reservation *f = bpf_map_lookup_elem(&reservation_ops_map, flow);
	if(f) {
		return SK_PASS;
	}
	curr_connection = bpf_map_lookup_elem(&existed_counter_map, &key);
	if(!curr_connection) {
		struct connection initial_conn;
		initial_conn.count = 0;
		char v = DEFAULT_KEY_OR_VALUE;
		if(bpf_map_update_elem(&existed_counter_map, &key, &v, BPF_NOEXIST) < 0)
			printk("Socket: Not found the existed connection map, pass for system stability\n");
		return SK_DROP;
	}
	if(curr_connection->count >= MAX_CONN) {
		return SK_DROP;
	}
//	__u64 start = bpf_ktime_get_ns();
	if(!f) {
		struct reservation reserv;
		reserv.last_updated = getBootTimeSec();
		ret = bpf_map_update_elem(&reservation_ops_map, flow, &reserv, BPF_NOEXIST);
	}
//	__u64 end = bpf_ktime_get_ns();
//	printk("Update time: %llu\n", end-start);
    if(ret != 0) {
        printk("Failed: failed to update map, return code: %d\n", ret);
		return SK_DROP;
    } else {
        (void) __sync_add_and_fetch(&curr_connection->count, 1);
        printk("Success: Add flow to existed connection.\n");
		return SK_PASS;
    }
} 

static inline
int ignored_tcp(unsigned int state) {
	int ans = 0;
	switch (state)
	{
	case BPF_TCP_ESTABLISHED:
		ans = 1;
		break;
	case BPF_TCP_FIN_WAIT1:
		ans = 1;
		break;
	case BPF_TCP_FIN_WAIT2:
		ans = 1;
		break;
	case BPF_TCP_TIME_WAIT:
		ans = 1;
		break;
	case BPF_TCP_CLOSE:
		ans = 1;
		break;
	case BPF_TCP_CLOSE_WAIT:
		ans = 1;
		break;
	case BPF_TCP_LAST_ACK:
		ans = 1;
		break;
	case BPF_TCP_CLOSING:
		ans = 1;
		break;
	case BPF_TCP_NEW_SYN_RECV:
		ans = 1;
		break;
	default:
		break;
	}
	return ans;
}

// Program for dispatching packets to sockets
__section("filter")
int cgroup_socket_drop(struct __sk_buff *skb)
{
	// __u16 port = skb->local_port;
	// if(port != (unsigned short)SWIFT_PROXY_SERVER_PORT) {
	// 	return SK_PASS;
	// }
	void *data = (void *)(long)skb->data;
  	void *data_end = (void *)(long)skb->data_end;
	
	__u8 ip = skb->protocol == bpf_htons(ETH_P_IP);
	if(ip) {
		if (data + sizeof(struct iphdr) > data_end) { return 0; }
		 struct iphdr *ip = data;
		 
		 __u8 tcp = ip->protocol == IPPROTO_TCP;
		 if(tcp) {
			__u8 *ihlandversion = data;
			__u8 ihlen = (*ihlandversion & 0xf) * 4;
			if (data + ihlen + sizeof(struct tcphdr) > data_end) { return 0; }
			struct tcphdr *tcp = data + ihlen;
			// Notice: tcp daddr & dest means client
			//				saddr & source means server
			if(tcp->source != bpf_htons(SWIFT_PROXY_SERVER_PORT)) {
				return SK_PASS;
			}
			if(skb->sk) {
				if(ignored_tcp(skb->sk->state)) {
					return SK_PASS;
				}
			}

			if(tcp->fin == 1) {
				printk("Socket: Let TCP packet pass\n");
				return SK_PASS;
			}
			if(tcp->rst == 1) {
				printk("RST!!\n");
				return SK_PASS;
			}

			struct flow_key flow;
			extract_key4_from_skb(ip->daddr, tcp->dest, &flow);
			if(tcp->syn == 1 && tcp->ack == 1) {
				printk("Socket: Receive syn-ack flag, try to add entry to existed connection...\n");
				return bpf_sock_ipv4(&flow);
			}
		 }
	}
    return SK_PASS;
}

char __license[] __section("license") = "GPL";