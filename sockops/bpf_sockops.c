#include <linux/bpf.h>
#include <asm-generic/socket.h>
#include <netinet/tcp.h>

#include "bpf_sockops.h"

/*
 * extract the key identifying the socket source of the TCP event
 */
static inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct flow_key *flow)
{
 //   flow->server_ip4 = ops->local_ip4;
 //   flow->server_port = (bpf_htonl(ops->local_port) >> 16);
	flow->client_ip4 = ops->remote_ip4;
	flow->client_port = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void delete_sock_from_maps(struct flow_key *flow) {
    __u32 key = 0;
    struct connection *curr_connection;
    curr_connection = bpf_map_lookup_elem(&existed_connection_map, &key);
    if(!curr_connection) {
        printk("Socket: Not found the existed connection map\n");
        return;
    }

    if(bpf_map_delete_elem(&reservation_ops_map, flow) < 0) {
        printk("Error: delete flow from map\n");
        return;
    }
    (void) __sync_add_and_fetch(&curr_connection->count, -1);
    
    printk("Success: delete flow from map\n");
}

// static void print_ip(unsigned int ip)
// {
//     unsigned char bytes[4];
//     bytes[0] = ip & 0xFF;
//     bytes[1] = (ip >> 8) & 0xFF;
//     bytes[2] = (ip >> 16) & 0xFF;
//     bytes[3] = (ip >> 24) & 0xFF;   

// 	printk("%d.%d.%d\n", bytes[2], bytes[1], bytes[0]);
// }

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    // AF_INET
    if(skops->family != 2) {
        return 0;
    }
    
    // flow->sip4:flow->sport == server IP: server port
    // flow->dip4:flow->dport == client IP: client port
    if((bpf_ntohl((bpf_htonl(skops->local_port) >> 16)) >> 16) != SWIFT_PROXY_SERVER_PORT) {
        return 0;
    }

    int rv = skops->reply;
    struct timeval timeout;      
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

        //    rv = bpf_setsockopt(skops, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        //    rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        //    rv += bpf_setsockopt(skops, SOL_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout));
            break;
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        //     bpf_sock_ops_ipv4(skops, &flow);
        //     bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

        //    rv = bpf_setsockopt(skops, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        //    rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        //    rv += bpf_setsockopt(skops, SOL_TCP, TCP_USER_TIMEOUT, &timeout, sizeof timeout);
            break;
        case BPF_SOCK_OPS_STATE_CB:
         //   printk("old state: %d, new state: %d\n", skops->args[0], skops->args[1]);
            if(skops->args[1] == BPF_TCP_CLOSE) {
                struct flow_key flow = {};
                extract_key4_from_ops(skops, &flow);
                printk("A socket being closed, try to delete flow from existed connection\n");
                delete_sock_from_maps(&flow);
            }
            break;
        default:
            break;
    }
    skops->reply = rv;
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
