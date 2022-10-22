#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "tc_classify_kern_pping_common.h"

int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
		exit(0);
	}
	return fd;
}

void dump(int fd) {
    union tc_handle_type key;
    union tc_handle_type *prev_key = NULL;
	struct rotating_performance perf;
	int err;
	int i = 0;
    printf("[\n");
	while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_lookup_elem(fd, &key, &perf);
        float total = 0;
        int n = 0;
        float min = 1000000.0;
        float max = 0.0;
        for (int i=0; i<MAX_PERF_SECONDS; ++i) {
            //printf("\ni=%d,rtt=0x%X\n", i, perf.rtt[i]);
            if (perf.rtt[i] != 0) {
                float this_reading = (float)perf.rtt[i]/100.0f;
                total += this_reading;
                n++;
                if (perf.rtt[i] < min) min = this_reading;
                if (perf.rtt[i] > max) max = this_reading;
            }
        }
        //printf("Next element: %d\n", perf.next_entry);
        if (n > 0) {
            printf("{");
            printf("\"tc\":\"%u:%u\"", key.majmin[1], key.majmin[0]);
            printf(", \"avg\": %.2f", total / (float)n);
            printf(", \"min\": %.2f", min);
            printf(", \"max\": %.2f", max);
            printf(", \"samples\": %d", n);
            printf("},\n");
        }
		prev_key = &key;
		i++;
	}
    printf("{}]\n");
}


/* Dumps all current RTT feeds in JSON format */
void cleanup_rtt(int fd) {
    int err;
    union tc_handle_type key;
    union tc_handle_type *prev_key = NULL;
    while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_delete_elem(fd, &key);
    }
}

/* Dumps all current RTT feeds in JSON format */
void cleanup_flowstate(int fd) {
    int err;
    struct network_tuple key;
    struct network_tuple *prev_key = NULL;
    while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_delete_elem(fd, &key);
    }
}

/* Dumps all current RTT feeds in JSON format */
void cleanup_packet_ts(int fd) {
    int err;
    struct packet_id key;
    struct packet_id *prev_key = NULL;
    while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_delete_elem(fd, &key);
    }
}

int main(int argc, char **argv)
{
    int rtt_tracker = open_bpf_map("/sys/fs/bpf/tc/globals/rtt_tracker");
    int flow_state = open_bpf_map("/sys/fs/bpf/tc/globals/flow_state");
    int packet_ts = open_bpf_map("/sys/fs/bpf/tc/globals/packet_ts");
    dump(rtt_tracker);
    cleanup_rtt(rtt_tracker);
    cleanup_flowstate(flow_state);
    cleanup_packet_ts(packet_ts);

    close(rtt_tracker);
    close(flow_state);
    close(packet_ts);
}