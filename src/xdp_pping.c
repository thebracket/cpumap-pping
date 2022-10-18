#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>

//FIXME: This should be gathered via a common header...
#define MAX_PERF_SECONDS 60
#define NS_PER_MS 1000000UL

struct rotating_performance {
    __u32 rtt[MAX_PERF_SECONDS];
    __u32 next_entry;
};

union tc_handle_type {
    __u32 handle;
    __u16 majmin[2];
};

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

void dump() {

    int fd = open_bpf_map("/sys/fs/bpf/tc/globals/rtt_tracker");

    union tc_handle_type key;
    union tc_handle_type *prev_key = NULL;
	struct rotating_performance perf;
	int err;
	int i = 0;
    printf("[\n");
	while ((err = bpf_map_get_next_key(fd, prev_key, &key)) == 0) {
        bpf_map_lookup_elem(fd, &key, &perf);
        __u32 total = 0;
        __u32 n = 0;
        __u32 min = 0xFFFFFFFF;
        __u32 max = 0;
        for (int i=0; i<MAX_PERF_SECONDS; ++i) {
            //printf("\ni=%d,rtt=0x%X\n", i, perf.rtt[i]);
            if (perf.rtt[i] != 0) {
                total += perf.rtt[i];
                n++;
                if (perf.rtt[i] < min) min = perf.rtt[i];
                if (perf.rtt[i] > max) max = perf.rtt[i];
            }
        }
        //printf("Next element: %d\n", perf.next_entry);
        if (n > 0) {
            printf("{");
            printf("\"tc\":\"%u:%u\"", key.majmin[1], key.majmin[0]);
            printf(", \"avg\" : %u", total / n);
            printf(", \"min\" : %u", min);
            printf(", \"max\" : %u", max);
            printf(", \"samples\" : %d", n);
            printf("},\n");
        }
		prev_key = &key;
		i++;
	}

    close(fd);
    printf("{}]\n");

}


/* Dumps all current RTT feeds in JSON format */
void cleanup() {
}

int main(int argc, char **argv)
{
    dump();
    cleanup();
}