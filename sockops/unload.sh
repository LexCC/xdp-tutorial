#!/bin/bash
set -x

# Detach and unload the bpf_sockops_v4 program
sudo bpftool cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
sudo rm /sys/fs/bpf/bpf_sockops
sudo rm /sys/fs/bpf/reservation_ops_map
sudo rm /sys/fs/bpf/existed_counter_map

sudo bpftool cgroup detach /sys/fs/cgroup/unified/ egress pinned /sys/fs/bpf/cgroup-sock-drop
sudo rm /sys/fs/bpf/cgroup-sock-drop
sudo rm /sys/fs/bpf/burst_connection_map
sudo rm /sys/fs/bpf/lb_ips_map
sudo rm /sys/fs/bpf/hitch_to_proxy_map

