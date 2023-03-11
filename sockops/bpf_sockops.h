#include <bpf/bpf_helpers.h>
#include <linux/swab.h>


#ifndef __section
#define __section(NAME) 	\
	__attribute__((section(NAME), used))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohl(x)                 __builtin_bswap32(x)
# define __bpf_htonl(x)                 __builtin_bswap32(x)
# define __bpf_constant_ntohl(x)        ___constant_swab32(x)
# define __bpf_constant_htonl(x)        ___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohl(x)                 (x)
# define __bpf_htonl(x)                 (x)
# define __bpf_constant_ntohl(x)        (x)
# define __bpf_constant_htonl(x)        (x)
#else
# error "Check the compiler's endian detection."
#endif

#define bpf_htonl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif

#ifndef NANOSEC_PER_SEC 
#define NANOSEC_PER_SEC 1000000000
#endif

#ifndef ENABLE_THROTTLE_SYN
#define ENABLE_THROTTLE_SYN 0 // 0 disable, 1 enable
#endif

#ifndef SWIFT_PROXY_SERVER_PORT
#define SWIFT_PROXY_SERVER_PORT 443
#endif

#ifndef MAX_CONN
#define MAX_CONN 320
#endif

#ifndef SOCKET_TIMEOUT_SEC
#define SOCKET_TIMEOUT_SEC 1
#endif

#ifndef TCP_MAX_SYN_ACK_RETRY
#define TCP_MAX_SYN_ACK_RETRY 3
#endif

#ifndef BURST_COUNT
#define BURST_COUNT (MAX_CONN + (MAX_CONN >> 1))
#endif

#ifndef GATE_OPEN_INTERVAL
#define GATE_OPEN_INTERVAL 1
#endif

#ifndef DEFAULT_KEY_OR_VALUE
#define DEFAULT_KEY_OR_VALUE 0
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) 	\
	(*NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

#ifndef printk
#define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

/* ebpf helper function
 * The generated function is used for parameter verification
 * by the eBPF verifier
 */
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops,
			void *map, void *key, __u64 flags);

struct flow_key
{
	__u32 client_ip4;
	__u32 client_port;	
}__attribute__((__packed__));

struct connection {
	__u32 count;
};

struct burst_per_open {
	__u32 count;
	__u32 last_updated; // sec as unit, ~136 yr. as upper bound
};

struct reservation {
	__u32 last_updated;
	__u32 syn_ack_retry;
};

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8  family;
	__u8  pad1;
	__u16 pad2;
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

#ifndef COMPILE_BTF
#define COMPILE_BTF 1
#endif

#if COMPILE_BTF == 1
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, sizeof(__u32));
	__type(value, sizeof(struct connection));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} existed_counter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, sizeof(__u32));
	__type(value, sizeof(struct burst_per_open));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} burst_connection_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONN);
	__type(key, sizeof(struct flow_key));
	__type(value, sizeof(struct reservation));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} reservation_ops_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, sizeof(__u32));
	__type(value, sizeof(char));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lb_ips_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65535);
	__type(key, sizeof(struct sock_key));
	__type(value, sizeof(int));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hitch_to_proxy_map SEC(".maps");

#else

struct bpf_map_def SEC("maps") existed_counter_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct connection),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") burst_connection_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct burst_per_open),
	.max_entries = 1,
};

struct bpf_map_def __section("maps") reservation_ops_map = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct flow_key),
	.value_size     = sizeof(struct reservation),
	.max_entries    = MAX_CONN,
	.map_flags      = 0,
};

struct bpf_map_def __section("maps") lb_ips_map = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(char),
	.max_entries    = 100,
	.map_flags      = 0,
};

struct bpf_map_def __section("maps") hitch_to_proxy_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};
#endif

static __always_inline
__u32 getBootTimeSec() {
	return (__u32) (bpf_ktime_get_ns() / NANOSEC_PER_SEC);
}

