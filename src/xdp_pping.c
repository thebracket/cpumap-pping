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
#include <arpa/inet.h>
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

int compare( const void* a, const void* b)
{
     return *((__u32*)a)-*((__u32*)b);
}

void print_ipv4or6(struct in6_addr *ip) {
    char ip_txt[INET6_ADDRSTRLEN] = {0};
    if (ip->__in6_u.__u6_addr32[0] == 0xFFFFFFFF && ip->__in6_u.__u6_addr32[1] == 0xFFFFFFFF && ip->__in6_u.__u6_addr32[2] == 0xFFFFFFFF) {
		// It's IPv4
		inet_ntop(AF_INET, &ip->__in6_u.__u6_addr32[3], ip_txt, sizeof(ip_txt));
	} else {
		// It's IPv6
		inet_ntop(AF_INET6, ip, ip_txt, sizeof(ip_txt));
	}
    printf("%s", ip_txt);
}

void dump(int fd) {
    __u32 key;
    __u32 *prev_key = NULL;
	struct rotating_performance perf;
	int err;
	int i = 0;
    printf("[\n");
    __u32 rtt[MAX_PERF_SECONDS];
	while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_lookup_elem(fd, &key, &perf);
        // Work on a local copy and sort it to help with obtaining the median
        memcpy(&rtt, &perf.rtt, MAX_PERF_SECONDS * sizeof(__u32));
        qsort(&rtt, MAX_PERF_SECONDS, sizeof(__u32), compare);
        union tc_handle_type handle;
        handle.handle = perf.tc_handle;
        float total = 0;
        int n = 0;
        float min = 1000000.0;
        float max = 0.0;
        for (int i=0; i<perf.next_entry; ++i) {
            if (rtt[i] != 0) {
                float this_reading = (float)rtt[i]/100.0f;
                total += this_reading;
                n++;
                if (rtt[i] < min) min = this_reading;
                if (rtt[i] > max) max = this_reading;
            }
        }
        float median = (float)rtt[(perf.next_entry - n) + MAX_PERF_SECONDS/2]/100.0;
        //printf("Next element: %d\n", perf.next_entry);
        if (n > 0) {
            printf("{");
            printf("\"tc\":\"%u:%u\"", handle.majmin[1], handle.majmin[0]);
            printf(", \"avg\": %.2f", total / (float)n);
            printf(", \"min\": %.2f", min);
            printf(", \"max\": %.2f", max);
            printf(", \"median\": %.2f", median);
            printf(", \"samples\": %d", n);
            printf(", \"localIp\": \"");
            print_ipv4or6(&perf.local_address);
            printf("\"");
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