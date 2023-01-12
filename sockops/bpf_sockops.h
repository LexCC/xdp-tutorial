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
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops,
			void *map, void *key, __u64 flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);


struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8  family;
	__u8  pad1;   // this padding required for 64bit alignment
	__u16 pad2;   // else ebpf kernel verifier rejects loading of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct flow_key
{
	__u32 sip4;
	__u32 dip4;
	__u32 pad1;
	__u32 pad2;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_map_def __section("maps") reservation_ops_map = {
	.type           = BPF_MAP_TYPE_LRU_HASH,
	.key_size       = sizeof(struct flow_key),
	.value_size     = sizeof(int),
	.max_entries    = 1024,
	.map_flags      = 0,
};

struct bpf_map_def __section("maps") sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};


