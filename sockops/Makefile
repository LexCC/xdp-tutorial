# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern
USER_TARGETS := xdp_loader
USER_TARGETS += xdp_stats
USER_TARGETS += psi_monitor
XDP_TARGETS  += bpf_sockops
XDP_TARGETS  += cgroup-sock-drop

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o

include $(COMMON_DIR)/common.mk
