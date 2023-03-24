#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define CPU_TRACKING_WINDOW_MS    500
#define IO_TRACKING_WINDOW_MS     500
#define CPU_TRIGGER_THRESHOLD_MS    100
#define IO_TRIGGER_THRESHOLD_MS     100
#define CPU_PRESSURE_FILE           "/proc/pressure/cpu"
#define IO_PRESSURE_FILE            "/proc/pressure/io"
#define FD_CPU_IDX                  0
#define FD_IO_IDX                   1

struct pollfd fds[2];
char *pin_basedir =  "/sys/fs/bpf";
char *psi_mapfile = "psi_map";

/*
 One function that prints the system call and the error details
 and then exits with error code 1. Non-zero meaning things didn't go well.
 */
void fatal_error(const char *syscall)
{
    perror(syscall);
    exit(1);
}

int get_map_fd_id(char *pin_dir, char *mapname, struct bpf_map_info *info)
{
	return open_bpf_map_file(pin_dir, mapname, info);
}

/*
 * PSI allows programs to wait for events related to pressure stalls
 * via poll() so that they can avoid continuously polling files in the
 * /proc/pressure directory.
 *
 * We setup to be notified via poll for two types of PSI events, one
 * for CPU and the other for I/O.
 *
 * */

void setup_polling() {
    /* Let's first setup our CPU PSI trigger */
    fds[FD_CPU_IDX].fd = open(CPU_PRESSURE_FILE, O_RDWR | O_NONBLOCK);
    if (fds[FD_CPU_IDX].fd < 0)
        fatal_error("open(): " CPU_PRESSURE_FILE);

    /* Next, our I/O PSI trigger */
    fds[FD_IO_IDX].fd = open(IO_PRESSURE_FILE, O_RDWR | O_NONBLOCK);
    if (fds[FD_IO_IDX].fd < 0)
        fatal_error("open(): " IO_PRESSURE_FILE);

    fds[FD_CPU_IDX].events = fds[FD_IO_IDX].events = POLLPRI;

    char trigger[128];
    snprintf(trigger, 128, "some %d %d", CPU_TRIGGER_THRESHOLD_MS * 1000, CPU_TRACKING_WINDOW_MS * 1000);
    printf("Trigger: %s\n", trigger);
    if (write(fds[FD_CPU_IDX].fd, trigger, strlen(trigger) + 1) < 0)
        fatal_error("write(): " CPU_PRESSURE_FILE);
    snprintf(trigger, 128, "some %d %d", IO_TRIGGER_THRESHOLD_MS * 1000, IO_TRACKING_WINDOW_MS * 1000);
    printf("Trigger: %s\n", trigger);
    if (write(fds[FD_IO_IDX].fd, trigger, strlen(trigger) + 1) < 0)
        fatal_error("write(): " IO_PRESSURE_FILE);
}


/*
 * This is the main function where we wait for notifications from
 * PSI. We increment 2 separate variables that track CPU and I/O
 * notification counts separately and print them.
 * */

 struct event_counter {
    __u32 cpu;
    __u32 io;
    __u32 last_updated;
    __u32 record_cpu_per_sec[60];
    __u32 record_cpu_index;
    __u32 record_io_per_sec[60];
    __u32 record_io_index;
 };

int get_past_probability(struct event_counter *event, int index, int fd_idx) {
    int i;
    __u32 total = 0;
    int start, prevent_overflow;
    if(fd_idx == FD_CPU_IDX) {
        start = event->record_cpu_index-1;
        for(i = 0; i < index; i++) {
            prevent_overflow = ((start--)+60) % 60;
            total += event->record_cpu_per_sec[prevent_overflow];
        }
    } else {
        start = event->record_io_index-1;
        for(i = 0; i < index; i++) {
            prevent_overflow = ((start--)+60) % 60;
            total += event->record_io_per_sec[prevent_overflow];
        }
    }
    if(total == 0 || total < index) {
        return 0;
    }
    
    return total / index;
}

void wait_for_notification(int psi_map_fd) {
    char default_conn_key = 0;
    int default_value = 0;
    if(bpf_map_update_elem(psi_map_fd, &default_conn_key, &default_value, BPF_ANY) < 0) {
        printf("initialize map value error\n");
        return;
    }     

    const int phase = 4;
    const int phases[] = {1, 4, 8, 10};
    int current_phase = 0;
    int high_pressure = 0;
    struct event_counter record = {0};
   // memset(&record.record_cpu_per_sec, sizeof(record.record_cpu_per_sec), 0);
    struct timespec t;
    const int fd_timeout_sec = 1;
    if (clock_gettime(CLOCK_BOOTTIME, &t) >= 0) {
		record.last_updated = (__u32)t.tv_sec;
	}
    while (1) {
        int n = poll(fds, 2, fd_timeout_sec * 1000);
        if (n < 0) {
            fatal_error("poll()");
        }
        // struct bpf_map_info psi_map_info = { 0 };
        // int detect_psi_map_reload = get_map_fd_id(pin_basedir, psi_mapfile, &psi_map_info);
        // if(detect_psi_map_reload >= 0 && psi_map_info.id != psi_map_fd) {
        //     printf("%d\n", detect_psi_map_reload);
        //     printf("%d\n", psi_map_fd);
        //     return;
        // }
        
        for (int i = 0; i < 2; i++) {

            /* If the fd of the current iteration does not have any
             * events, move on to the next fd.
             * */
            if (fds[i].revents == 0)
                continue;

            if (fds[i].revents & POLLERR) {
                fprintf(stderr, "Error: poll() event source is gone.\n");
                exit(1);
            }
            if (fds[i].revents & POLLPRI) {
                if (i == FD_CPU_IDX)
                    record.cpu++;
                else
                    record.io++;
            } else {
                fprintf(stderr, "Unrecognized event: 0x%x.\n", fds[i].revents);
                exit(1);
            }
        }
        // The way to calculate threshold:
        //      1 sec
        // |-----|-----|
        //  500ms 500ms
        // So if we focus on window 500 ms, and we notice that the events triggered more than twice
        // in past 1 sec, that should not be ideal case
        // Probablity Formula: ((event triggered count) * window) * 100 (For translate to percentage%) / measured unit
        // e.g. (2 * 500ms * 100%) / 1000 (1sec * 1000) = 100%
        if (clock_gettime(CLOCK_BOOTTIME, &t) >= 0 && (__u32)t.tv_sec - record.last_updated >= 1) {
            __u32 period = (t.tv_sec - record.last_updated) * 1000;
            record.last_updated = (__u32)t.tv_sec;
            // record pressure percentage per second
            record.record_cpu_per_sec[record.record_cpu_index++] = (record.cpu * CPU_TRACKING_WINDOW_MS * 100) / period;
            record.record_io_per_sec[record.record_io_index++] = (record.io * IO_TRACKING_WINDOW_MS * 100) / period;
            record.record_cpu_index %= 60;
            record.record_io_index %= 60;
            if(get_past_probability(&record, phases[current_phase], FD_CPU_IDX) > 50) {
                current_phase++;
            } else {
                current_phase--;
            }
            
            if(current_phase >= phase-1) {
                if(high_pressure == 0) {
                    high_pressure = 1;
                    if(bpf_map_update_elem(psi_map_fd, &default_conn_key, &high_pressure, BPF_EXIST) < 0)
                        printf("update map error\n");
                    printf("Lock!\n");
                }
                current_phase = phase-1;
            }
            if(current_phase < 0) {
                if(high_pressure == 1) {
                    high_pressure = 0;
                    if(bpf_map_update_elem(psi_map_fd, &default_conn_key, &high_pressure, BPF_EXIST) < 0)
                        printf("update map error\n");
                    printf("Release!\n");
                }
                current_phase = 0;
            }
            record.cpu = 0;
            record.io = 0;
        }
    }
}

/*
 * We check for tell-tale signs of the running kernel supporting PSI.
 * Else, we print a friendly message and exit.
 * */

void check_basics() {
    struct stat st;
    int sret = stat(CPU_PRESSURE_FILE, &st);
    if (sret == -1) {
        fprintf(stderr, "Error! Your kernel does not expose pressure stall information.\n");
        fprintf(stderr, "You may want to check if you have Linux Kernel v5.2+ with PSI enabled.\n");
        exit(1);
    }
}

int get_psi_map_fd() {
    struct bpf_map_info map_expect = { 0 };
    struct bpf_map_info psi_map_info = { 0 };
    int psi_map_fd, err;

    psi_map_fd = get_map_fd_id(pin_basedir, psi_mapfile, &psi_map_info);
    if(psi_map_fd < 0) {
        return -1;
    }
    err = check_map_fd_info(&psi_map_info, &map_expect);
    if(err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
		close(psi_map_fd);
		return -1;
    }
    return psi_map_fd;
}

int main() {
    check_basics();
    setup_polling();
    while(1) {
        int psi_map_fd = get_psi_map_fd();
        if(psi_map_fd < 0) {
            continue;
        }
        wait_for_notification(psi_map_fd);
        close(psi_map_fd);
    }
    
    return EXIT_SUCCESS;
}