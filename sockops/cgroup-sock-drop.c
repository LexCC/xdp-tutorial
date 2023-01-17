
#include <linux/bpf.h>
#include "bpf_sockops.h"

#define SK_DROP 0
#define SK_PASS 1




/* User accessible data for SK_LOOKUP programs. Add new fields at the end. */
struct bpf_sk_lookup {
	__bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket */

	__u32 family;        /* Protocol family (AF_INET, AF_INET6) */
	__u32 protocol;      /* IP protocol (IPPROTO_TCP, IPPROTO_UDP) */
	__u32 remote_ip4;    /* Network byte order */
	__u32 remote_ip6[4]; /* Network byte order */
	__u32 remote_port;   /* Network byte order */
	__u32 local_ip4;     /* Network byte order */
	__u32 local_ip6[4];  /* Network byte order */
	__u32 local_port;    /* Host byte order */
};

// Program for dispatching packets to sockets
__section("filter")
int cgroup_socket_drop(struct __sk_buff *skb)
{
	__u16 port = skb->local_port;
	if(port != (unsigned short)8080) {
		return SK_PASS;
	}
    
    return SK_DROP;
}

char __license[] __section("license") = "GPL";