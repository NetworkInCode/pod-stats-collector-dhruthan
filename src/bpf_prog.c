#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pod_stats.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PODS);
    __type(key, __u32);
    __type(value, struct pod_stats);
} pod_stats_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pod_stats *stats;
    
    stats = bpf_map_lookup_elem(&pod_stats_map, &pid);
    if (!stats) {
        struct pod_stats new_stats = {0};
        new_stats.timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&new_stats.pod_name, sizeof(new_stats.pod_name));
        bpf_map_update_elem(&pod_stats_map, &pid, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&pod_stats_map, &pid);
        if (!stats)
            return 0;
    }
    
    __sync_fetch_and_add(&stats->open_files, 1);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pod_stats *stats;
    
    stats = bpf_map_lookup_elem(&pod_stats_map, &pid);
    if (!stats)
        return 0;
    
    stats->timestamp = bpf_ktime_get_ns();
    return 0;
}

char _license[] SEC("license") = "GPL";
