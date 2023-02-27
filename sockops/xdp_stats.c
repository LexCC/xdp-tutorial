#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#ifndef NANOSEC_PER_SEC 
#define NANOSEC_PER_SEC 1000000000
#endif

#ifndef ACK_TIME_OUT
#define ACK_TIME_OUT 10 /* Sec as unit */
#endif

#ifndef GARBAGE_COLLECT_PERIOD
#define GARBAGE_COLLECT_PERIOD 2 /* Sec as unit, the value should less than ACK_TIME_OUT */
#endif
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

int get_map_fd_id(char *pin_dir, char *mapname, struct bpf_map_info *info)
{
	return open_bpf_map_file(pin_dir, mapname, info);
}

void find_expired_connection(int reservation_ops_map_fd, int existed_counter_map_fd) 
{
	struct timespec t;
	if (clock_gettime(CLOCK_BOOTTIME, &t) < 0) {
		return;
	}

	struct flow_key key= { 0 }, next_key;
	int res;
	struct reservation value;
	struct connection *total;
	__u32 default_conn_key = 0;
	int entries = 0, kick_off = 0;
	res = bpf_map_lookup_elem(existed_counter_map_fd, &default_conn_key, &total);
	if(res < 0 || !total) {
		return;
	}

	while(bpf_map_get_next_key(reservation_ops_map_fd, &key, &next_key) == 0) {
		entries++;
		res = bpf_map_lookup_elem(reservation_ops_map_fd, &next_key, &value);
		key=next_key;
		if(res < 0 || value.last_updated == 0) {
			continue;
		}
		
		if((__u32) t.tv_sec - value.last_updated > ACK_TIME_OUT) {
			if(bpf_map_delete_elem(reservation_ops_map_fd, &key) < 0) {
				kick_off++;
			}
		}
	}
	int real_num = entries - kick_off;
	if(bpf_map_update_elem(existed_counter_map_fd, &default_conn_key, &real_num, BPF_EXIST) < 0) {
		printf("update map error\n");
	} else {
		printf("update map success\n");
	}
	
}

// static int stats_poll(int reservation_map_fd, int connection_map_fd)
// {
// 	/* Trick to pretty printf with thousands separators use %' */
// 	setlocale(LC_NUMERIC, "en_US");

// //	int dectection;
// 	while (1) {
// 		/*TODO: Keep it for detect bpf program reload*/
// 		prev = record;
// 		dectection = get_map_fd_id(pin_dir, mapname, info);
// 		if (dectection < 0) {
// 			return EXIT_FAIL_BPF;
// 		}
// 		if(map_id != info->id) {
// 			fprintf(stderr,
// 			"ERR: Detect new bpf program loaded\n");
// 			close(dectection);
// 			return 0;
// 		}
// 		// close(map_fd);
// 		// sleep(interval);
// 	}
// 	return 0;
// }

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

char *pin_basedir =  "/sys/fs/bpf";
char *reservation_mapfile = "reservation_ops_map";
char *connection_mapfile = "existed_counter_map";
char *lbips_mapfile = "lb_ips_map";

void configure_lb_ips()
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info lbips_map_info = { 0 };
	int lbips_map_fd, err;
	lbips_map_fd = get_map_fd_id(pin_basedir, lbips_mapfile, &lbips_map_info);
	if (lbips_map_fd < 0) {
		return;
	}
	err = check_map_fd_info(&lbips_map_info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(lbips_map_fd);
		return;
	}

	FILE *lb_ips_cfg;
	size_t len = 0;
    ssize_t read;
	char *ip = NULL;
	lb_ips_cfg = fopen("./lb_ips.cfg", "r");
	if(lb_ips_cfg == NULL) {
		return;
	}
	int i;
	const int MAX_LB_IPS = 1024;
	int total_lb_ips = 0;
	__u32 lb_ips_list[MAX_LB_IPS];
	for(i=0; i<MAX_LB_IPS; i++) { lb_ips_list[i] = 0; }

	while((read = getline(&ip, &len, lb_ips_cfg)) != -1) {
		int a,b,c,d;
		sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
		__u32 ip_2_bin = (a << 24) + (b << 16) + (c << 8) + d;
		lb_ips_list[total_lb_ips++] = bpf_htonl(ip_2_bin);
	}
	
	
	int res;
	char* value;
	char default_value = 0;
	// Append new LB IP to map
	for(i=0; i<total_lb_ips; i++) {
		__u32 key = lb_ips_list[i];
		res = bpf_map_lookup_elem(lbips_map_fd, &key, value);
		if(res < 0 && !value) {
			if(bpf_map_update_elem(lbips_map_fd, &key, &default_value, BPF_NOEXIST) < 0) {
				printf("Append new LB IP error\n");
			}
		}
	}

	// Remove LB IP from map which is not existed in configuration file
	__u32 key = 0, next_key;
	while(bpf_map_get_next_key(lbips_map_fd, &key, &next_key) == 0) {
		res = bpf_map_lookup_elem(lbips_map_fd, &next_key, &value);
		key=next_key;
		if(res < 0) {
			continue;
		}
		int found = 0;
		for(i=0; i<total_lb_ips; i++) {
			if(next_key == lb_ips_list[i]) {
				found = 1;
				break;
			}
		}
		if(found == 0) {
			if(bpf_map_delete_elem(lbips_map_fd, &next_key) < 0) {
				printf("Remove old LB IP error\n");
			}
		}
	}

	fclose(lb_ips_cfg);
	if(ip)
		free(ip);
	close(lbips_map_fd);
}

int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info reservation_map_info = { 0 };
	struct bpf_map_info connection_map_info = { 0 };
	int reservation_map_fd, connection_map_fd;
	int err;
	int show_map_info_once = 1;

	configure_lb_ips();
	
	for(;;) {
		reservation_map_fd = get_map_fd_id(pin_basedir, reservation_mapfile, &reservation_map_info);
		connection_map_fd = get_map_fd_id(pin_basedir, connection_mapfile, &connection_map_info);
		if (reservation_map_fd < 0 || connection_map_fd < 0) {
			return EXIT_FAILURE;
		}

		err = check_map_fd_info(&reservation_map_info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(reservation_map_fd);
			return err;
		}

		err = check_map_fd_info(&connection_map_info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(connection_map_fd);
			return err;
		}
		if(show_map_info_once) {
			printf("\nCollecting stats from BPF map\n");
			printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
				" key_size:%d value_size:%d max_entries:%d\n",
				reservation_map_info.type, reservation_map_info.id, reservation_map_info.name,
				reservation_map_info.key_size, reservation_map_info.value_size, reservation_map_info.max_entries
				);
			printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
				" key_size:%d value_size:%d max_entries:%d\n",
				connection_map_info.type, connection_map_info.id, connection_map_info.name,
				connection_map_info.key_size, connection_map_info.value_size, connection_map_info.max_entries
				);
			show_map_info_once = 0;
		}
		find_expired_connection(reservation_map_fd, connection_map_fd);
		close(reservation_map_fd);
		close(connection_map_fd);
		sleep(GARBAGE_COLLECT_PERIOD);
	}
	
	return EXIT_SUCCESS;
}
