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
	flow->client_ip4 = ops->remote_ip4;
	flow->client_port = FORCE_READ(ops->remote_port) >> 16;
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

static inline
void extract_hitch_to_proxy_key(struct bpf_sock_ops *ops, struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dip4 = ops->remote_ip4;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void record_if_hitch_to_proxy(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    int ret;

    extract_hitch_to_proxy_key(skops, &key);

    ret = sock_hash_update(skops, &hitch_to_proxy_map, &key, BPF_NOEXIST);
    if (ret != 0) {
        printk("sock_hash_update() failed, ret: %d\n", ret);
    }

    printk("sockmap: op %d, port %d --> %d\n",
            skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

static inline
void delete_sock_from_maps(struct flow_key *flow) {
	if(!flow)
		return;
    __u32 key = DEFAULT_KEY_OR_VALUE;
    struct connection *curr_connection;
    curr_connection = bpf_map_lookup_elem(&existed_counter_map, &key);
    if(!curr_connection) {
        printk("Socket: Not found the existed connection map\n");
        return;
    }
 //   __u64 start = bpf_ktime_get_ns();
    // struct reservation *reserv = bpf_map_lookup_elem(&reservation_ops_map, flow);
    // if(reserv)
    //     printk("Timestamp: %ld\n", reserv->last_updated);
    int ret = bpf_map_delete_elem(&reservation_ops_map, flow);
    if(ret < 0) {
//        printk("Delete time: %llu\n", bpf_ktime_get_ns()-start);
        printk("Error: delete flow from map\n");
        return;
    }
//    printk("Delete time: %llu\n", bpf_ktime_get_ns()-start);
    (void) __sync_add_and_fetch(&curr_connection->count, -1);
    printk("Success: delete flow from map\n");
}

static inline
void update_ack_timestamp(struct flow_key *flow) {
    struct reservation value;
    value.last_updated = 0;
    value.syn_ack_retry = 0;
    if(bpf_map_update_elem(&reservation_ops_map, flow, &value, BPF_EXIST) < 0) {
        printk("Can't update ack timestamp\n");
    }
    return;
}

/* 0: false, 1: true*/
static inline
int is_local_hitch_to_proxy(struct bpf_sock_ops *skops) {
    if(bpf_ntohl(skops->remote_port) != 8080) {
        return 0;
    }

    __u32 localhost_ip = bpf_htonl(0b01111111000000000000000000000001);
    if(skops->remote_ip4 != localhost_ip || skops->local_ip4 != localhost_ip) {
        return 0;
    }
    printk("Is hitch to proxy\n");
    return 1;
} 

/* 0: false, 1: true*/
static inline
int is_request_proxy_server(struct bpf_sock_ops *skops) {
    if((bpf_ntohl((bpf_htonl(skops->local_port) >> 16)) >> 16) != SWIFT_PROXY_SERVER_PORT) {
        return 0;
    }
    return 1;
}
__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    // AF_INET
    if(skops->family != 2) {
        return 0;
    }
    
    // flow->sip4:flow->sport == server IP: server port
    // flow->dip4:flow->dport == client IP: client port
    if(is_local_hitch_to_proxy(skops) == 0 && is_request_proxy_server(skops) == 0) {
        return 0;
    }

    int rv = skops->reply;
    struct timeval timeout;      
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
            // struct linger ling;
            // ling.l_onoff = 1;
            // ling.l_linger = 0;
            //   rv = bpf_setsockopt(skops, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
          // rv = bpf_setsockopt(skops, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
          // rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
          // rv += bpf_setsockopt(skops, SOL_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout));
           struct flow_key flow = {};
           extract_key4_from_ops(skops, &flow);
           update_ack_timestamp(&flow);
            break;
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            printk("An active connection!!!\n");
            record_if_hitch_to_proxy(skops);
            break;
        case BPF_SOCK_OPS_STATE_CB:
          // printk("old state: %d, new state: %d\n", skops->args[0], skops->args[1]);
            if(skops->args[0] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE) {
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
    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
