#include <linux/bpf.h>

#include "bpf_sockops.h"


/*
 * extract the key that identifies the destination socket in the sock_ops_map
 */
static inline
void extract_key4_from_msg(struct sk_msg_md *msg, struct sock_key *key)
{
    key->sip4 = msg->remote_ip4;
    key->dip4 = msg->local_ip4;
    key->family = 1;

    key->dport = (bpf_htonl(msg->local_port) >> 16);
    key->sport = FORCE_READ(msg->remote_port) >> 16;
}

/* 0: false, 1: true*/
// static inline
// int is_local_hitch_to_proxy(struct sk_msg_md *msg)
// {
//     __u32 localhost_ip = bpf_htonl(0b01111111000000000000000000000001);
//     if(msg->remote_ip4 != localhost_ip || msg->local_ip4 != localhost_ip) {
//         return 0;
//     }
//     if(msg->local_port != 8080 && bpf_ntohl(msg->remote_port) != 8080) {
//         return 0;
//     }
//     return 1;
// }

__section("sk_msg")
int hitch_to_proxy(struct sk_msg_md *msg)
{
    // if(is_local_hitch_to_proxy(msg) == 0) {
    //     return SK_PASS;
    // }
    struct sock_key key = {};
    extract_key4_from_msg(msg, &key);
    msg_redirect_hash(msg, &hitch_to_proxy_map, &key, BPF_F_INGRESS);
    return SK_PASS;
}

char ____license[] __section("license") = "GPL";