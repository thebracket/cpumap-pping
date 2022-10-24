#ifndef __MAXIMUMS_H
// Maximum number of TC class mappings to support
#define IP_HASH_ENTRIES_MAX	65534
// Maximum number of TCP flows to track at once
#define MAX_FLOWS IP_HASH_ENTRIES_MAX*2
// Maximum number of packet pairs to track per flow.
#define MAX_PACKETS MAX_FLOWS

#define __MAXIMUMS_H
#endif