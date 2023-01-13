#include <linux/bpf.h>

#include "bpf_sockops.h"

/*
 * extract the key identifying the socket source of the TCP event
 */
static inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct flow_key *flow)
{
    flow->sip4 = ops->local_ip4;
	flow->dip4 = ops->remote_ip4;
	flow->dport = FORCE_READ(ops->remote_port) >> 16;
	flow->sport = (bpf_htonl(ops->local_port) >> 16);
}

/*
 * Insert socket into sockmap
 */
static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops, struct flow_key *flow)
{ 
    int ret;

    int v = 1;
    __u32 key = 0;
    struct connection *curr_connection;
    curr_connection = bpf_map_lookup_elem(&existed_connection_map, &key);
    if(!curr_connection) {
        printk("Socket: Not found the existed connection map\n");
        return;
    }

    if(curr_connection->count >= MAX_CONN) {
        printk("Socket: Existed connection are saturated!!!\n");
        return;
    }

    ret = bpf_map_update_elem(&reservation_ops_map, flow, &v, BPF_NOEXIST);
    if(ret != 0) {
        printk("bpf_map_update_elem() failed, ret: %d\n", ret);
    } else {
        (void) __sync_add_and_fetch(&curr_connection->count, 1);
        printk("update map success, ret: %d\n", ret);
    }
}

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    // AF_INET
    if(skops->family != 2) {
        return 0;
    }

    struct flow_key flow = {};
    extract_key4_from_ops(skops, &flow);
    if(flow.dport != (bpf_htonl(SWIFT_PROXY_SERVER_PORT) >> 16)) {
        return 0;
    }
    
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            bpf_sock_ops_ipv4(skops, &flow);
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_ops_ipv4(skops, &flow);
            break;
        default:
            break;
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
