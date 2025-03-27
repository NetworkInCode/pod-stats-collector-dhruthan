#ifndef __POD_STATS_H
#define __POD_STATS_H

#define MAX_PODS 1024
#define TASK_COMM_LEN 16

struct pod_stats {
    __u64 open_files;
    __u64 rss_bytes;
    __u64 timestamp;
    char pod_name[64];
};

#endif /* __POD_STATS_H */
