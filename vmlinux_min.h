#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef unsigned short int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef unsigned long long int __u64;
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u32 pid_t;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u32 __poll_t;

#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sched_process_template {
    struct trace_entry ent;
    char comm[16];
    pid_t pid;
    int prio;
};

struct trace_event_raw_sched_switch {
    struct trace_entry ent;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};

#pragma clang attribute pop
#endif
