#include <linux/bpf.h>

#include "bpf_sockops.h"

#ifndef PACKET_PER_MS_SOCKET_REDIRECT_ENABLE
#define PACKET_PER_MS_SOCKET_REDIRECT_ENABLE 12500
#endif

/* 0:disable, 1:enable */
int ENABLE_SOCKET_REDIRECT = 0;

struct bpf_spin_lock lock;

/* Record feature time */
int FEATURE_OPEN_AT = 0;
int FEATURE_CLOSE_AT = 0;

struct socket_redirect_record {
    __u32 last_updated;
	__u32 redir_count;
    __u32 bytes_per_ms;
};

struct socket_redirect_record socket_redirect_analyzer[MAX_CPU_CORES] = {0};

/*
 * extract the key that identifies the destination socket in the sock_ops_map
 */
static inline
void extract_key4_from_msg(struct sk_msg_md *msg, struct sock_key *key)
{
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
//     if(msg->local_port == 8080 || bpf_ntohl(msg->remote_port) == 8080) {
//         return 1;
//     }
//     return 0;
// }

// __u32 getBootTimeMILLISec() {
// 	return (__u32) (bpf_ktime_get_ns() / NANOSEC_PER_MILLISEC);
// }

// static __always_inline
// __u32 sub(__u32 a, __u32 b) {
//     if(a > b) {
//         return a - b;
//     }
//     return b - a;
// }

// static __always_inline
// /* 0: unlikely, 1: likely */
// int isSimilar(__u32 a, __u32 b, __u32 c, int threshold) {
//     __u32 mu = (a+b+c) / 3;
//     __u32 variance = (sub(mu, a) + sub(mu, b) + sub(mu, c)) / 3;
//     // printk("-----------\n");
//     // printk("%ld %ld %ld", a, b, c);
//     // printk("variance: %d\n", variance);
//     // printk("-----------\n");
//     if(variance < threshold) {
//         return 1;
//     }
//     return 0;
// }

// static __always_inline
// __u32 calculate_bytes_per_ms(struct socket_redirect_record current, __u32 curr_time) {
//     if(curr_time - current.last_updated <= 0) {
//         return 0;
//     }
//     if(current.redir_count <= 0) {
//         return 0;
//     }
//     return current.redir_count / (curr_time - current.last_updated);   
// }

// static __always_inline
// void detect_enable_redirect_feature(__u32 core_id, __u32 pkt_per_ms) {
//     if(pkt_per_ms <= PACKET_PER_MS_SOCKET_REDIRECT_ENABLE) {
//         return;
//     }
//     __u32 curr_time = getBootTimeMILLISec();
//     // To prevent enable/diable switching frequently, wait 10 sec for re-enable the feature
//     if(curr_time - FEATURE_CLOSE_AT < 10000) {
//         return;
//     }
//     // Assume that redir_count have similar value on all cpus when met the huge traffic
//     // In this case, just pick head and tail cpu as reference,
//     // and calculate standard deviation, so that we can guess the discrete value on all cpus
//    // __u32 curr_time = getBootTimeMILLISec();
//     __u32 a = (core_id >= 0 && core_id < MAX_CPU_CORES) ? core_id : 0;
//     __u32 b = 1;
//     __u32 c = 0;
    
//     __u32 tdab = sub(socket_redirect_analyzer[a].last_updated, socket_redirect_analyzer[b].last_updated);
//     __u32 tdac = sub(socket_redirect_analyzer[a].last_updated, socket_redirect_analyzer[c].last_updated);
//     __u32 tdbc = sub(socket_redirect_analyzer[b].last_updated, socket_redirect_analyzer[c].last_updated);
//     const int time_diff_threshold = 60000; // 1 min
//     if(tdab > time_diff_threshold || tdac > time_diff_threshold || tdbc > time_diff_threshold) {
//         return;
//     }
//     const int threshold = 20000;
//     if(isSimilar(socket_redirect_analyzer[a].bytes_per_ms, socket_redirect_analyzer[b].bytes_per_ms, socket_redirect_analyzer[c].bytes_per_ms, threshold) == 1) {
//         // turn the feature on
//         printk("enable\n");
//        // bpf_spin_lock(&lock);
//         FEATURE_OPEN_AT = curr_time;
//        // bpf_spin_unlock(&lock);
//         ENABLE_SOCKET_REDIRECT = 1;
//     }   
// }

// static __always_inline
// void detect_disable_redirect_feature(__u32 core_id, __u32 pkt_per_ms) {
//     if(pkt_per_ms > PACKET_PER_MS_SOCKET_REDIRECT_ENABLE / 2) {
//         return;
//     }
//     __u32 a = (core_id >= 0 && core_id < MAX_CPU_CORES) ? core_id : 0;
//     __u32 b = 1;
//     __u32 c = 0;
//     __u32 curr_time = getBootTimeMILLISec();
//     __u32 ta = sub(socket_redirect_analyzer[a].last_updated, curr_time);
//     __u32 tb = sub(socket_redirect_analyzer[b].last_updated, curr_time);
//     __u32 tc = sub(socket_redirect_analyzer[c].last_updated, curr_time);
//     const int time_diff_threshold = 120000; // 2 min
//     // If kernel met huge traffic, there's no core should be not updated more than 2 min
//     // so we condsider this as kernel is not busy, turn off redirect feature
//     if(ta > time_diff_threshold || tb > time_diff_threshold || tc > time_diff_threshold) {
//        // bpf_spin_lock(&lock);
//         FEATURE_CLOSE_AT = curr_time;
//        // bpf_spin_unlock(&lock);
//         ENABLE_SOCKET_REDIRECT = 0;
//         printk("disable\n");
//         return;
//     }
//     const int threshold = 1000;
//     if(isSimilar(socket_redirect_analyzer[a].bytes_per_ms, socket_redirect_analyzer[b].bytes_per_ms, socket_redirect_analyzer[c].bytes_per_ms, threshold) == 1) {
//       //  bpf_spin_lock(&lock);
//         FEATURE_CLOSE_AT = curr_time;
//       //  bpf_spin_unlock(&lock);
//         ENABLE_SOCKET_REDIRECT = 0;
//         printk("disable\n");
//     }
// }

// static __always_inline
// void record_socket_redirect_per_cpu(int core_id, __u32 msg_size) {
//     return;
//     if(core_id < 0) {
//         return;
//     }
//     int size = sizeof(socket_redirect_analyzer) / sizeof(socket_redirect_analyzer[0]);
//     if(core_id < size) {
//         struct socket_redirect_record *current = &socket_redirect_analyzer[core_id];
    
    
//         if(current->last_updated == 0) {
//             current->last_updated = getBootTimeMILLISec();
//             current->redir_count = 1;
//             return;
//         }

//         current->redir_count += msg_size;
        
//         // Check packets redirection time for each 1000 ms
//         __u32 curr_time = getBootTimeMILLISec();
//         if(curr_time - current->last_updated > 1000) {
//            __u32 bytes_per_ms = calculate_bytes_per_ms(*current, curr_time);
//            // update
//            current->last_updated = curr_time;
//            current->bytes_per_ms = bytes_per_ms;
//            // reset
//            current->redir_count = 0;
//             if(ENABLE_SOCKET_REDIRECT == 0) {
//                 detect_enable_redirect_feature(core_id, bytes_per_ms);
//             } else {
//                 // To prevent enable/diable switching frequently, keep 10 min once feature open
//                 if(FEATURE_OPEN_AT - curr_time < 6000000) {
//                     return;
//                 }
//                 detect_disable_redirect_feature(core_id, bytes_per_ms);
//             }
//         }
//     }
// }

__section("sk_msg")
int hitch_to_proxy(struct sk_msg_md *msg)
{
    // if(is_local_hitch_to_proxy(msg) == 0) {
    //     return SK_PASS;
    // }
    
   // record_socket_redirect_per_cpu((int)bpf_get_smp_processor_id(), msg->size);
    // if(ENABLE_SOCKET_REDIRECT == 0) {
    //     return SK_PASS;
    // }
    
    
    struct sock_key key = {};
    extract_key4_from_msg(msg, &key);
    msg_redirect_hash(msg, &hitch_to_proxy_map, &key, BPF_F_INGRESS);
    return SK_PASS;
}

char ____license[] __section("license") = "GPL";