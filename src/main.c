#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include "pod_stats.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static __u64 get_rss_bytes(__u32 pid) {
    char path[32];
    FILE *f;
    unsigned long rss_pages = 0;

    snprintf(path, sizeof(path), "/proc/%u/statm", pid);
    f = fopen(path, "r");
    if (f) {
        fscanf(f, "%*lu %lu", &rss_pages);
        fclose(f);
    }
    return rss_pages * 4096; // Assuming 4K pages
}

static int get_pod_name(__u32 pid, char *pod_name, size_t pod_name_len) {
    char path[32];
    char line[512];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
    f = fopen(path, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "kubepods")) {
            // Look for pod UID in the format "pod<uid>.slice"
            char *pod_start = strstr(line, "pod");
            if (pod_start) {
                // "kubepods-<type>-pod<uid>.slice" pattern
                char *uid_start = pod_start;
                while (uid_start > line && *(uid_start - 1) != '-') {
                    uid_start--; // Move back to find the start of "pod<uid>"
                }
                if (uid_start == pod_start) {
                    uid_start = pod_start;
                }

                char *uid_end = strstr(uid_start, ".slice");
                if (!uid_end) {
                    uid_end = strchr(uid_start, '/');
                }
                if (!uid_end) {
                    uid_end = uid_start + strlen(uid_start);
                }

                size_t len = uid_end - uid_start;
                if (len >= pod_name_len)
                    len = pod_name_len - 1;

                // Extract the full pod identifier
                strncpy(pod_name, "pod-", 5);
                size_t prefix_len = strlen(pod_name);
                strncpy(pod_name + prefix_len, uid_start, len);
                pod_name[prefix_len + len] = '\0';

                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1; // Not a pod
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog_openat, *prog_switch;
    struct bpf_link *link_openat = NULL, *link_switch = NULL;
    int map_fd, err;

    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file("src/bpf_prog.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    prog_openat = bpf_object__find_program_by_name(obj, "trace_openat");
    if (!prog_openat) {
        fprintf(stderr, "Failed to find trace_openat program\n");
        goto cleanup;
    }
    link_openat = bpf_program__attach(prog_openat);
    if (libbpf_get_error(link_openat)) {
        fprintf(stderr, "Failed to attach trace_openat: %s\n", strerror(errno));
        goto cleanup;
    }

    prog_switch = bpf_object__find_program_by_name(obj, "trace_sched_switch");
    if (!prog_switch) {
        fprintf(stderr, "Failed to find trace_sched_switch program\n");
        goto cleanup;
    }
    link_switch = bpf_program__attach(prog_switch);
    if (libbpf_get_error(link_switch)) {
        fprintf(stderr, "Failed to attach trace_sched_switch: %s\n", strerror(errno));
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "pod_stats_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map: %d\n", map_fd);
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\033[1mCollecting Kubernetes Pod Statistics (Press Ctrl+C to stop)\033[0m\n");
    printf("\033[4m%-48s %-10s %-15s %-10s\033[0m\n", "POD NAME", "PID", "OPEN FILES", "RSS (MB)");

    #define MAX_SEEN_PIDS 1024
    struct { __u32 pid; struct pod_stats stats; int seen; char pod_name[64]; } seen_pids[MAX_SEEN_PIDS] = {0};
    int num_seen = 0;

    while (!exiting) {
        __u32 key, next_key;
        struct pod_stats stats;

        key = 0;
        num_seen = 0;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                char real_pod_name[64] = {0};
                if (get_pod_name(next_key, real_pod_name, sizeof(real_pod_name)) == 0) {
                    stats.rss_bytes = get_rss_bytes(next_key);

                    int i, found = 0;
                    for (i = 0; i < num_seen; i++) {
                        if (seen_pids[i].pid == next_key) {
                            seen_pids[i].stats = stats;
                            found = 1;
                            break;
                        }
                    }
                    if (!found && num_seen < MAX_SEEN_PIDS) {
                        seen_pids[num_seen].pid = next_key;
                        seen_pids[num_seen].stats = stats;
                        strncpy(seen_pids[num_seen].pod_name, real_pod_name, sizeof(seen_pids[num_seen].pod_name));
                        seen_pids[num_seen].seen = 0;
                        num_seen++;
                    }
                }
            }
            key = next_key;
        }

        printf("\033[2J\033[H");
        printf("\033[1mCollecting Kubernetes Pod Statistics (Press Ctrl+C to stop)\033[0m\n");
        printf("\033[4m%-48s %-10s %-15s %-10s\033[0m\n", "POD NAME", "PID", "OPEN FILES", "RSS (MB)");

        for (int i = 0; i < num_seen; i++) {
            printf("%-48s %-10u %-15lu %-10.2f\n",
                   seen_pids[i].pod_name,
                   seen_pids[i].pid,
                   seen_pids[i].stats.open_files,
                   seen_pids[i].stats.rss_bytes / (1024.0 * 1024.0));
        }
        fflush(stdout);
        sleep(2);
    }

cleanup:
    if (link_openat)
        bpf_link__destroy(link_openat);
    if (link_switch)
        bpf_link__destroy(link_switch);
    bpf_object__close(obj);
    return err != 0;
}
