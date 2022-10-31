/* SPDX-License-Identifier: GPL-2.0 */
/*
Copyright 2022 Herbert Wolverson
Licensed under the GNU General Purpose License 2
See LICENSE file for details.
*/
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

int main(int argc, char **argv)
{
    int rtt_tracker = open_bpf_map("/sys/fs/bpf/tc/globals/rtt_tracker");
    dump(rtt_tracker);
    cleanup_rtt(rtt_tracker);

    close(rtt_tracker);
}