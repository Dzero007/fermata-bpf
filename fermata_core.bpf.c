// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct exit_event { u32 pid; };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} cpu_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} run_start SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct exit_event *ev = bpf_ringbuf_reserve(&exit_events, sizeof(*ev), 0);
    if (!ev) return 0;
    ev->pid = BPF_CORE_READ(ctx, pid);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
    u32 next_pid = BPF_CORE_READ(ctx, next_pid);
    u64 now = bpf_ktime_get_ns();
    if (prev_pid > 0) {
        u64 *start = bpf_map_lookup_elem(&run_start, &prev_pid);
        if (start && now > *start) {
            u64 delta = now - *start;
            u64 *total = bpf_map_lookup_elem(&cpu_time, &prev_pid);
            if (total) *total += delta;
            else bpf_map_update_elem(&cpu_time, &prev_pid, &delta, BPF_ANY);
        }
    }
    if (next_pid > 0) bpf_map_update_elem(&run_start, &next_pid, &now, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
