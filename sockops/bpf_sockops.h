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

#ifndef SWIFT_PROXY_SERVER_PORT
#define SWIFT_PROXY_SERVER_PORT 4000
#endif

#ifndef MAX_CONN
#define MAX_CONN 1
#endif

#ifndef SOCKET_TIMEOUT_SEC
#define SOCKET_TIMEOUT_SEC 1
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) 	\
	(*NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
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

struct flow_key
{
	__u32 sip4;
	__u32 dip4;
	__u32 pad1;
	__u32 pad2;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct connection {
	__u32 count;
};

struct bpf_map_def SEC("maps") existed_connection_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct connection),
	.max_entries = 1,
};

struct bpf_map_def __section("maps") reservation_ops_map = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct flow_key),
	.value_size     = sizeof(int),
	.max_entries    = MAX_CONN,
	.map_flags      = 0,
};


