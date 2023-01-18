
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
 //   flow->server_ip4 = ops->local_ip4;
 //   flow->server_port = (bpf_htonl(ops->local_port) >> 16);
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
    int ret;

    char v = 0;
    __u32 key = 0;
    struct connection *curr_connection;
    curr_connection = bpf_map_lookup_elem(&existed_connection_map, &key);
    if(!curr_connection) {
        printk("Socket: Not found the existed connection map, pass for system stability\n");
        return 0;
    }

    if(curr_connection->count >= MAX_CONN) {
        printk("Socket: Existed connection are saturated!!!\n");
        return -1;
    }
//	__u64 start = bpf_ktime_get_ns();
    ret = bpf_map_update_elem(&reservation_ops_map, flow, &v, BPF_NOEXIST);
//	__u64 end = bpf_ktime_get_ns();
//	printk("Update time: %llu\n", end-start);
    if(ret != 0) {
        printk("Failed: failed to update map, return code: %d\n", ret);
		return -1;
    } else {
        (void) __sync_add_and_fetch(&curr_connection->count, 1);
        printk("Success: Add flow to existed connection.\n");
		return 0;
    }
}

// Program for dispatching packets to sockets
__section("filter")
int cgroup_socket_drop(struct __sk_buff *skb)
{
	__u16 port = skb->local_port;
	if(port != (unsigned short)SWIFT_PROXY_SERVER_PORT) {
		return SK_PASS;
	}
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
			// Notice: tcp daddr & dest means server
			//				saddr & source means client
			if(tcp->source != bpf_htons(SWIFT_PROXY_SERVER_PORT)) {
				return SK_PASS;
			}
			if(tcp->syn == 1 && tcp->ack == 1) {
				printk("Socket: Receive syn-ack flag, try to add entry to existed connection...\n");
				struct flow_key flow;
				extract_key4_from_skb(ip->daddr, tcp->dest, &flow);
				if(bpf_sock_ipv4(&flow) < 0) {
					return SK_DROP;
				}
				
			}
		 }
	}
    return SK_PASS;
}

char __license[] __section("license") = "GPL";