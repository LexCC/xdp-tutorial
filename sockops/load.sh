#!/bin/bash

# enable debug output for each executed command, to disable: set +x
set -x

# exit if any command fails
set -e


#MAP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-)


sudo bpftool prog load bpf_sockops.o /sys/fs/bpf/bpf_sockops map name reservation_ops_map pinned /sys/fs/bpf/reservation_ops_map map name existed_connection_map pinned /sys/fs/bpf/existed_connection_map
sudo bpftool cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
# sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops_map
# sudo bpftool -p map dump id

