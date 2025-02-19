#!/bin/bash

# enable debug output for each executed command, to disable: set +x
set -x

# exit if any command fails
set -e

# plz make sure bpf map path have mounted
#mount -t bpf bpf /sys/fs/bpf/

#MAP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-)


sudo bpftool prog load bpf_sockops.o /sys/fs/bpf/bpf_sockops map name reservation_ops_map pinned /sys/fs/bpf/reservation_ops_map map name existed_counter_map pinned /sys/fs/bpf/existed_counter_map map name burst_connection_map pinned /sys/fs/bpf/burst_connection_map map name lb_ips_map pinned /sys/fs/bpf/lb_ips_map map name psi_map pinned /sys/fs/bpf/psi_map
sudo bpftool cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
# sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops_map
# sudo bpftool -p map dump id


sudo bpftool prog load cgroup-sock-drop.o /sys/fs/bpf/cgroup-sock-drop map name reservation_ops_map pinned /sys/fs/bpf/reservation_ops_map map name existed_counter_map pinned /sys/fs/bpf/existed_counter_map map name burst_connection_map pinned /sys/fs/bpf/burst_connection_map map name lb_ips_map pinned /sys/fs/bpf/lb_ips_map map name psi_map pinned /sys/fs/bpf/psi_map type cgroup/skb
sudo bpftool cgroup attach /sys/fs/cgroup/unified/ egress pinned /sys/fs/bpf/cgroup-sock-drop
