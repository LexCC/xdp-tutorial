#!/bin/bash
set -x

# Detach and unload the bpf_redir program
sudo bpftool prog detach pinned /sys/fs/bpf/bpf_redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
sudo rm /sys/fs/bpf/bpf_redir

# Detach and unload the bpf_sockops_v4 program
sudo bpftool cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
sudo rm /sys/fs/bpf/bpf_sockops
sudo rm /sys/fs/bpf/reservation_ops_map

# Delete the map
sudo rm /sys/fs/bpf/sock_ops_map
