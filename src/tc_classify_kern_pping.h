/* Implementation of pping inside the kernel
 * classifier
 */
#ifndef __TC_CLASSIFY_KERN_PPING_H
#define __TC_CLASSIFY_KERN_PPING_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define MAX_MEMCMP_SIZE 128
#define DELAY_BETWEEN_RTT_REPORTS_MS 1000

#define DEBUG 1
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = "(tc) " fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })
#else
#define bpf_debug(fmt, ...) \
    {                       \
    }                       \
    while (0)
#endif

typedef __u64 fixpoint64;
#define FIXPOINT_SHIFT 16
#define DOUBLE_TO_FIXPOINT(X) ((fixpoint64)((X) * (1UL << FIXPOINT_SHIFT)))
#define FIXPOINT_TO_UINT(X) ((X) >> FIXPOINT_SHIFT)

union iph_ptr
{
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
};

struct parsing_context
{
    void *data;
    void *data_end;
    __u32 l3_offset;
    union iph_ptr ip_header;
    __u32 skb_len;
    struct in6_addr *saddr;
    struct in6_addr *daddr;
    __be16 protocol;
    struct tcphdr *tcp;
};

/* Event type recorded for a packet flow */
enum __attribute__((__packed__)) flow_event_type
{
    FLOW_EVENT_NONE,
    FLOW_EVENT_OPENING,
    FLOW_EVENT_CLOSING,
    FLOW_EVENT_CLOSING_BOTH
};

/* Detailed reason for an event. Probably can be removed. */
enum __attribute__((__packed__)) flow_event_reason
{
    EVENT_REASON_NONE,
    EVENT_REASON_SYN,
    EVENT_REASON_SYN_ACK,
    EVENT_REASON_FIRST_OBS_PCKT,
    EVENT_REASON_FIN,
    EVENT_REASON_RST,
    EVENT_REASON_FLOW_TIMEOUT
};

enum __attribute__((__packed__)) connection_state
{
    CONNECTION_STATE_EMPTY,
    CONNECTION_STATE_WAITOPEN,
    CONNECTION_STATE_OPEN,
    CONNECTION_STATE_CLOSED
};

enum __attribute__((__packed__)) pping_map
{
    PPING_MAP_FLOWSTATE = 0,
    PPING_MAP_PACKETTS
};

/*
 * Struct that can hold the source or destination address for a flow (l3+l4).
 * Works for both IPv4 and IPv6, as IPv4 addresses can be mapped to IPv6 ones
 * based on RFC 4291 Section 2.5.5.2.
 */
struct flow_address
{
    struct in6_addr ip;
    __u16 port;
    __u16 reserved;
};

/*
 * Struct to hold a full network tuple
 * The ipv member is technically not necessary, but makes it easier to
 * determine if saddr/daddr are IPv4 or IPv6 address (don't need to look at the
 * first 12 bytes of address). The proto memeber is not currently used, but
 * could be useful once pping is extended to work for other protocols than TCP.
 *
 * Note that I've removed proto, ipv and reserved.
 */
struct network_tuple
{
    struct flow_address saddr;
    struct flow_address daddr;
    __u16 proto; // IPPROTO_TCP, IPPROTO_ICMP, QUIC etc
    __u8 ipv;    // AF_INET or AF_INET6
    __u8 reserved;
};

static __always_inline void debug_network_tuple(struct network_tuple *key) {
    /*bpf_debug("Key: %u : %u", key->saddr.ip.in6_u.u6_addr32[3], key->saddr.port);
    bpf_debug("     %u : %u", key->daddr.ip.in6_u.u6_addr32[3], key->daddr.port);
    bpf_debug("     %u, %u", key->proto, key->reserved);*/
}

struct flow_state
{
    __u64 min_rtt;
    __u64 srtt;
    __u64 last_timestamp;
    __u64 sent_pkts;
    __u64 sent_bytes;
    __u64 rec_pkts;
    __u64 rec_bytes;
    __u32 last_id;
    __u32 outstanding_timestamps;
    enum connection_state conn_state;
    enum flow_event_reason opening_reason;
    __u8 reserved[6];
};

/*
 * Stores flowstate for both direction (src -> dst and dst -> src) of a flow
 *
 * Uses two named members instead of array of size 2 to avoid hassels with
 * convincing verifier that member access is not out of bounds
 */
struct dual_flow_state
{
    struct flow_state dir1;
    struct flow_state dir2;
};

struct packet_id
{
    struct network_tuple flow;
    __u32 identifier;
};

/*
 * Struct filled in by parse_packet_id.
 *
 * Note: As long as parse_packet_id is successful, the flow-parts of pid
 * and reply_pid should be valid, regardless of value for pid_valid and
 * reply_pid valid. The *pid_valid members are there to indicate that the
 * identifier part of *pid are valid and can be used for timestamping/lookup.
 * The reason for not keeping the flow parts as an entirely separate members
 * is to save some performance by avoid doing a copy for lookup/insertion
 * in the packet_ts map.
 */
struct packet_info
{
    __u64 time;                 // Arrival time of packet
    __u32 payload;              // Size of packet data (excluding headers)
    struct packet_id pid;       // flow + identifier to timestamp (ex. TSval)
    struct packet_id reply_pid; // rev. flow + identifier to match against (ex. TSecr)
    __u32 ingress_ifindex;      // Interface packet arrived on (if is_ingress, otherwise not valid)
    union
    { // The IP-level "type of service" (DSCP for IPv4, traffic class + flow label for IPv6)
        __u8 ipv4_tos;
        __be32 ipv6_tos;
    } ip_tos;
    __u16 ip_len;                        // The IPv4 total length or IPv6 payload length
    bool is_ingress;                     // Packet on egress or ingress?
    bool pid_flow_is_dfkey;              // Used to determine which member of dualflow state to use for forward direction
    bool pid_valid;                      // identifier can be used to timestamp packet
    bool reply_pid_valid;                // reply_identifier can be used to match packet
    enum flow_event_type event_type;     // flow event triggered by packet
    enum flow_event_reason event_reason; // reason for triggering flow event
};

/*
 * Struct filled in by protocol id parsers (ex. parse_tcp_identifier)
 */
struct protocol_info
{
    __u32 pid;
    __u32 reply_pid;
    bool pid_valid;
    bool reply_pid_valid;
    enum flow_event_type event_type;
    enum flow_event_reason event_reason;
};

/* For the event_type members of rtt_event and flow_event */
#define EVENT_TYPE_FLOW 1
#define EVENT_TYPE_RTT 2
#define EVENT_TYPE_MAP_FULL 3
#define EVENT_TYPE_MAP_CLEAN 4

/*
 * An RTT event message passed when an RTT has been calculated
 * Uses explicit padding instead of packing based on recommendations in cilium's
 * BPF reference documentation at https://docs.cilium.io/en/stable/bpf/#llvm.
 */
struct rtt_event
{
    __u64 event_type;
    __u64 timestamp;
    struct network_tuple flow;
    __u32 padding;
    __u64 rtt;
    __u64 min_rtt;
    __u64 sent_pkts;
    __u64 sent_bytes;
    __u64 rec_pkts;
    __u64 rec_bytes;
    bool match_on_egress;
    __u8 reserved[7];
};

/* Map Definitions */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct packet_id);
    __type(value, __u64);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} packet_ts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct network_tuple);
    __type(value, struct dual_flow_state);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flow_state SEC(".maps");

// Mask for IPv6 flowlabel + traffic class -  used in fib lookup
#define IPV6_FLOWINFO_MASK __cpu_to_be32(0x0FFFFFFF)

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define MAX_TCP_OPTIONS 10

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL
#define MS_PER_S 1000UL
#define S_PER_DAY (24 * 3600UL)

/* Functions */

static __always_inline void debug_increment_autodel(enum pping_map map)
{
#ifdef DEBUG
    //bpf_debug("Increment Autodel");
#endif
}

/*
 * Convenience function for getting the corresponding reverse flow.
 * PPing needs to keep track of flow in both directions, and sometimes
 * also needs to reverse the flow to report the "correct" (consistent
 * with Kathie's PPing) src and dest address.
 */
static __always_inline void reverse_flow(struct network_tuple *dest, struct network_tuple *src)
{
    dest->ipv = src->ipv;
    dest->proto = src->proto;
    dest->saddr = src->daddr;
    dest->daddr = src->saddr;
    dest->reserved = 0;
}

/*
 * Returns the number of unparsed bytes left in the packet (bytes after nh.pos)
 */
static __always_inline __u32 remaining_pkt_payload(struct parsing_context *ctx)
{
    // pkt_len - (pos - data) fails because compiler transforms it to pkt_len - pos + data (pkt_len - pos not ok because value - pointer)
    // data + pkt_len - pos fails on (data+pkt_len) - pos due to math between pkt_pointer and unbounded register
    void *nh_pos = (ctx->tcp + 1) + (ctx->tcp->doff << 2);
    __u32 parsed_bytes = nh_pos - ctx->data;
    return parsed_bytes < ctx->skb_len ? ctx->skb_len - parsed_bytes : 0;
}

/*
 * Send a map-full event for the map.
 * Will only trigger once every WARN_MAP_FULL_INTERVAL
 */
static __always_inline void send_map_full_event(void *ctx, struct packet_info *p_info,
                                                enum pping_map map)
{
    /*struct map_full_event me;

    if (p_info->time < last_warn_time[map] ||
        p_info->time - last_warn_time[map] < WARN_MAP_FULL_INTERVAL)
        return;

    last_warn_time[map] = p_info->time;

    __builtin_memset(&me, 0, sizeof(me));
    me.event_type = EVENT_TYPE_MAP_FULL;
    me.timestamp = p_info->time;
    me.flow = p_info->pid.flow;
    me.map = map;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &me, sizeof(me));*/
    bpf_debug("Map full event");
}

/*
 * Send a flow opening event through the perf-buffer.
 * As these events are only sent upon receiving a reply, need to access state
 * of the reverse flow to get reason flow was opened and when the original
 * packet opening the flow was sent.
 */
static __always_inline void send_flow_open_event(void *ctx, struct packet_info *p_info,
                                                 struct flow_state *rev_flow)
{
    /*struct flow_event fe = {
        .event_type = EVENT_TYPE_FLOW,
        .flow_event_type = FLOW_EVENT_OPENING,
        .source = EVENT_SOURCE_PKT_DEST,
        .flow = p_info->pid.flow,
        .reason = rev_flow->opening_reason,
        .timestamp = rev_flow->last_timestamp,
        .reserved = 0,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &fe, sizeof(fe));*/
    bpf_debug("Flow open event");
}

/*
 * Sends a flow-event message based on p_info.
 *
 * The rev_flow argument is used to inform if the message is for the flow
 * in the current direction or the reverse flow, and will adapt the flow and
 * source members accordingly.
 */
static __always_inline void send_flow_event(void *ctx, struct packet_info *p_info,
                                            bool rev_flow)
{
    /*struct flow_event fe = {
        .event_type = EVENT_TYPE_FLOW,
        .flow_event_type = p_info->event_type,
        .reason = p_info->event_reason,
        .timestamp = p_info->time,
        .reserved = 0, // Make sure it's initilized
    };

    if (rev_flow) {
        fe.flow = p_info->pid.flow;
        fe.source = EVENT_SOURCE_PKT_SRC;
    } else {
        fe.flow = p_info->reply_pid.flow;
        fe.source = EVENT_SOURCE_PKT_DEST;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &fe, sizeof(fe));*/
    bpf_debug("Send flow event");
}

/*
 * Can't seem to get __builtin_memcmp to work, so hacking my own
 *
 * Based on https://githubhot.com/repo/iovisor/bcc/issues/3559,
 * __builtin_memcmp should work constant size but I still get the "failed to
 * find BTF for extern" error.
 */
static __always_inline int my_memcmp(const void *s1_, const void *s2_, __u32 size)
{
    const __u8 *s1 = s1_, *s2 = s2_;
    int i;

    for (i = 0; i < MAX_MEMCMP_SIZE && i < size; i++)
    {
        if (s1[i] != s2[i])
            return s1[i] > s2[i] ? 1 : -1;
    }

    return 0;
}

static __always_inline bool is_dualflow_key(struct network_tuple *flow)
{
    return my_memcmp(&flow->saddr, &flow->daddr, sizeof(flow->saddr)) <= 0;
}

static __always_inline struct flow_state *fstate_from_dfkey(struct dual_flow_state *df_state,
                                                            bool is_dfkey)
{
    if (!df_state)
        return NULL;

    return is_dfkey ? &df_state->dir1 : &df_state->dir2;
}

/*
 * Parses the TSval and TSecr values from the TCP options field. If sucessful
 * the TSval and TSecr values will be stored at tsval and tsecr (in network
 * byte order).
 * Returns 0 if sucessful and -1 on failure
 */
static __always_inline int parse_tcp_ts(struct tcphdr *tcph, void *data_end, __u32 *tsval,
                                        __u32 *tsecr)
{
    int len = tcph->doff << 2;
    void *opt_end = (void *)tcph + len;
    __u8 *pos = (__u8 *)(tcph + 1); // Current pos in TCP options
    __u8 i, opt;
    volatile __u8
        opt_size; // Seems to ensure it's always read of from stack as u8

    if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
        return -1;
#pragma unroll // temporary solution until we can identify why the non-unrolled loop gets stuck in an infinite loop
    for (i = 0; i < MAX_TCP_OPTIONS; i++)
    {
        if (pos + 1 > opt_end || pos + 1 > data_end)
            return -1;

        opt = *pos;
        if (opt == 0) // Reached end of TCP options
            return -1;

        if (opt == 1)
        { // TCP NOP option - advance one byte
            pos++;
            continue;
        }

        // Option > 1, should have option size
        if (pos + 2 > opt_end || pos + 2 > data_end)
            return -1;
        opt_size = *(pos + 1);
        if (opt_size < 2) // Stop parsing options if opt_size has an invalid value
            return -1;

        // Option-kind is TCP timestap (yey!)
        if (opt == 8 && opt_size == 10)
        {
            if (pos + 10 > opt_end || pos + 10 > data_end)
                return -1;
            *tsval = bpf_ntohl(*(__u32 *)(pos + 2));
            *tsecr = bpf_ntohl(*(__u32 *)(pos + 6));
            return 0;
        }

        // Some other TCP option - advance option-length bytes
        pos += opt_size;
    }
    return -1;
}

/*
 * Attempts to fetch an identifier for TCP packets, based on the TCP timestamp
 * option.
 *
 * Will use the TSval as pid and TSecr as reply_pid, and the TCP source and dest
 * as port numbers.
 *
 * If successful, tcph, sport, dport and proto_info will be set
 * appropriately and 0 will be returned.
 * On failure -1 will be returned (and arguments will not be set).
 */
static __always_inline int parse_tcp_identifier(struct parsing_context *context,
                                                __u16 *sport,
                                                __u16 *dport, struct protocol_info *proto_info, bool is_wan)
{
    if (parse_tcp_ts(context->tcp, context->data_end, &proto_info->pid, &proto_info->reply_pid) < 0)
        return -1; // Possible TODO, fall back on seq/ack instead

    // Do not timestamp pure ACKs (no payload)
    void *nh_pos = (context->tcp + 1) + (context->tcp->doff << 2);
    proto_info->pid_valid =
        nh_pos - context->data < context->skb_len || context->tcp->syn;

    // Do not match on non-ACKs (TSecr not valid)
    proto_info->reply_pid_valid = context->tcp->ack;

    // Check if connection is opening/closing
    if (context->tcp->rst)
    {
        proto_info->event_type = FLOW_EVENT_CLOSING_BOTH;
        proto_info->event_reason = EVENT_REASON_RST;
    }
    else if (context->tcp->fin)
    {
        proto_info->event_type = FLOW_EVENT_CLOSING;
        proto_info->event_reason = EVENT_REASON_FIN;
    }
    else if (context->tcp->syn)
    {
        proto_info->event_type = FLOW_EVENT_OPENING;
        proto_info->event_reason =
            context->tcp->ack ? EVENT_REASON_SYN_ACK : EVENT_REASON_SYN;
    }
    else
    {
        proto_info->event_type = FLOW_EVENT_NONE;
        proto_info->event_reason = EVENT_REASON_NONE;
    }

    *sport = is_wan ? bpf_ntohs(context->tcp->source) : bpf_ntohs(context->tcp->dest);
    *dport = is_wan ? bpf_ntohs(context->tcp->dest) : bpf_ntohs(context->tcp->source);

    return 0;
}

/* This is a bit of a hackjob from the original */
static __always_inline int parse_packet_identifier(struct parsing_context *context, struct packet_info *p_info, bool is_wan)
{
    p_info->time = bpf_ktime_get_ns();
    if (context->protocol == ETH_P_IP)
    {
        p_info->pid.flow.ipv = AF_INET;
    }
    else if (context->protocol == ETH_P_IPV6)
    {
        p_info->pid.flow.ipv = AF_INET6;
    }
    else
    {
        bpf_debug("Unknown protocol");
        return -1;
    }

    struct protocol_info proto_info;
    int err = parse_tcp_identifier(context,
                                   &p_info->pid.flow.saddr.port,
                                   &p_info->pid.flow.daddr.port,
                                   &proto_info,
                                   is_wan);
    if (err)
        return -1;

    // Sucessfully parsed packet identifier - fill in remaining members and return
    p_info->pid.identifier = proto_info.pid;
    p_info->pid_valid = proto_info.pid_valid;
    p_info->reply_pid.identifier = proto_info.reply_pid;
    p_info->reply_pid_valid = proto_info.reply_pid_valid;
    p_info->event_type = proto_info.event_type;
    p_info->event_reason = proto_info.event_reason;

    // Apparently this is how you memcpy in BPF land?
    __builtin_memcpy(&p_info->pid.flow.saddr.ip, is_wan ? context->saddr : context->daddr, sizeof(struct in6_addr));
    __builtin_memcpy(&p_info->pid.flow.daddr.ip, is_wan ? context->daddr : context->saddr, sizeof(struct in6_addr));

    //bpf_debug("Source: %u : %u", p_info->pid.flow.saddr.ip.in6_u.u6_addr32[3], p_info->pid.flow.saddr.port);
    //bpf_debug("Dest: %u : %u", p_info->pid.flow.daddr.ip.in6_u.u6_addr32[3], p_info->pid.flow.daddr.port);
    if (p_info->pid.flow.ipv == AF_INET)
    {
        p_info->ip_len = bpf_ntohs(context->ip_header.iph->tot_len);
        p_info->ip_tos.ipv4_tos = context->ip_header.iph->tos;
    }
    else if (p_info->pid.flow.ipv == AF_INET6)
    { // IPv6
        p_info->ip_len = bpf_ntohs(context->ip_header.ip6h->payload_len);
        p_info->ip_tos.ipv6_tos =
            *(__be32 *)context->ip_header.ip6h & IPV6_FLOWINFO_MASK;
    }
    else
    {
        bpf_debug("Unknown internal protocol");
        return -1;
    }

    p_info->pid_flow_is_dfkey = is_dualflow_key(&p_info->pid.flow);

    reverse_flow(&p_info->reply_pid.flow, &p_info->pid.flow);
    p_info->payload = remaining_pkt_payload(context);

    return 0;
}

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static __always_inline void map_ipv4_to_ipv6(struct in6_addr *ipv6, __be32 ipv4)
{
    __builtin_memset(&ipv6->in6_u.u6_addr8[0], 0x00, 10);
    __builtin_memset(&ipv6->in6_u.u6_addr8[10], 0xff, 2);
    ipv6->in6_u.u6_addr32[3] = ipv4;
}

static __always_inline struct network_tuple *
get_dualflow_key_from_packet(struct packet_info *p_info)
{
    return p_info->pid_flow_is_dfkey ? &p_info->pid.flow : &p_info->reply_pid.flow;
}

/*
 * Initilizes an "empty" flow state based on the forward direction of the
 * current packet
 */
static __always_inline void init_flowstate(struct flow_state *f_state,
                                           struct packet_info *p_info)
{
    //bpf_debug("Called init flowstate");
    f_state->conn_state = CONNECTION_STATE_WAITOPEN;
    f_state->last_timestamp = p_info->time;
    f_state->opening_reason = p_info->event_type == FLOW_EVENT_OPENING ? p_info->event_reason : EVENT_REASON_FIRST_OBS_PCKT;
}

static __always_inline void init_empty_flowstate(struct flow_state *f_state)
{
    f_state->conn_state = CONNECTION_STATE_EMPTY;
}

static __always_inline struct flow_state *
get_flowstate_from_packet(struct dual_flow_state *df_state,
                          struct packet_info *p_info)
{
    return fstate_from_dfkey(df_state, p_info->pid_flow_is_dfkey);
}

static __always_inline struct flow_state *
get_reverse_flowstate_from_packet(struct dual_flow_state *df_state,
                                  struct packet_info *p_info)
{
    return fstate_from_dfkey(df_state, !p_info->pid_flow_is_dfkey);
}

/*
 * Initilize a new (assumed 0-initlized) dual flow state based on the current
 * packet.
 */
static __always_inline void init_dualflow_state(struct dual_flow_state *df_state,
                                                struct packet_info *p_info)
{
    struct flow_state *fw_state =
        get_flowstate_from_packet(df_state, p_info);
    struct flow_state *rev_state =
        get_reverse_flowstate_from_packet(df_state, p_info);

    init_flowstate(fw_state, p_info);
    init_empty_flowstate(rev_state);
}

static __always_inline struct dual_flow_state *
create_dualflow_state(void *ctx, struct packet_info *p_info, bool *new_flow)
{
    struct network_tuple *key = get_dualflow_key_from_packet(p_info);
    struct dual_flow_state new_state = {0};

    init_dualflow_state(&new_state, p_info);

    if (bpf_map_update_elem(&flow_state, key, &new_state, BPF_NOEXIST) ==
        0)
    {
        //bpf_debug("Insert tuple");
        debug_network_tuple(key);
        if (new_flow)
            *new_flow = true;
    }
    else
    {
        send_map_full_event(ctx, p_info, PPING_MAP_FLOWSTATE);
        return NULL;
    }

    return bpf_map_lookup_percpu_elem(&flow_state, key, bpf_get_smp_processor_id());
}

static __always_inline struct dual_flow_state *
lookup_or_create_dualflow_state(void *ctx, struct packet_info *p_info,
                                bool *new_flow)
{
    struct dual_flow_state *df_state;

    struct network_tuple * key = get_dualflow_key_from_packet(p_info);
    //bpf_debug("Search tuple");
    debug_network_tuple(key);
    df_state = bpf_map_lookup_elem(&flow_state, key);

    if (df_state)
    {
        //bpf_debug("Found flowstate");
        return df_state;
    }

    // Only try to create new state if we have a valid pid
    if (!p_info->pid_valid || p_info->event_type == FLOW_EVENT_CLOSING ||
        p_info->event_type == FLOW_EVENT_CLOSING_BOTH)
        return NULL;

    return create_dualflow_state(ctx, p_info, new_flow);
}

static __always_inline bool is_flowstate_active(struct flow_state *f_state)
{
    return f_state->conn_state != CONNECTION_STATE_EMPTY &&
           f_state->conn_state != CONNECTION_STATE_CLOSED;
}

static __always_inline void update_forward_flowstate(struct packet_info *p_info,
                                                     struct flow_state *f_state, bool *new_flow)
{
    // "Create" flowstate if it's empty
    if (f_state->conn_state == CONNECTION_STATE_EMPTY &&
        p_info->pid_valid)
    {
        init_flowstate(f_state, p_info);
        if (new_flow)
            *new_flow = true;
    }

    if (is_flowstate_active(f_state))
    {
        f_state->sent_pkts++;
        f_state->sent_bytes += p_info->payload;
    }
}

static __always_inline void update_reverse_flowstate(void *ctx, struct packet_info *p_info,
                                                     struct flow_state *f_state)
{
    if (!is_flowstate_active(f_state))
        return;

    // First time we see reply for flow?
    if (f_state->conn_state == CONNECTION_STATE_WAITOPEN &&
        p_info->event_type != FLOW_EVENT_CLOSING_BOTH)
    {
        f_state->conn_state = CONNECTION_STATE_OPEN;
        send_flow_open_event(ctx, p_info, f_state);
    }

    f_state->rec_pkts++;
    f_state->rec_bytes += p_info->payload;
}

static __always_inline bool should_notify_closing(struct flow_state *f_state)
{
    return f_state->conn_state == CONNECTION_STATE_OPEN;
}

static __always_inline bool is_new_identifier(struct packet_id *pid, struct flow_state *f_state)
{
    if (pid->flow.proto == IPPROTO_TCP)
        /* TCP timestamps should be monotonically non-decreasing
         * Check that pid > last_ts (considering wrap around) by
         * checking 0 < pid - last_ts < 2^31 as specified by
         * RFC7323 Section 5.2*/
        return pid->identifier - f_state->last_id > 0 &&
               pid->identifier - f_state->last_id < 1UL << 31;

    return pid->identifier != f_state->last_id;
}

static __always_inline bool is_rate_limited(__u64 now, __u64 last_ts, __u64 rtt)
{
    if (now < last_ts)
        return true;

    // RTT-based rate limit
    // if (config.rtt_rate && rtt)
    //	return now - last_ts < FIXPOINT_TO_UINT(config.rtt_rate * rtt);

    // Static rate limit
    return now - last_ts < DELAY_BETWEEN_RTT_REPORTS_MS * NS_PER_MS;
}

/*
 * Attempt to create a timestamp-entry for packet p_info for flow in f_state
 */
static __always_inline void pping_timestamp_packet(struct flow_state *f_state, void *ctx,
                                                   struct packet_info *p_info, bool new_flow)
{
    if (!is_flowstate_active(f_state) || !p_info->pid_valid)
        return;

    /*if (config.localfilt && p_info->is_ingress &&
        is_local_address(p_info, ctx))
        return;*/

    // Check if identfier is new
    if (!new_flow && !is_new_identifier(&p_info->pid, f_state))
        return;
    f_state->last_id = p_info->pid.identifier;

    // Check rate-limit
    if (!new_flow &&
        is_rate_limited(p_info->time, f_state->last_timestamp,
                        f_state->min_rtt))
        return;

    /*
     * Updates attempt at creating timestamp, even if creation of timestamp
     * fails (due to map being full). This should make the competition for
     * the next available map slot somewhat fairer between heavy and sparse
     * flows.
     */
    f_state->last_timestamp = p_info->time;

    if (bpf_map_update_elem(&packet_ts, &p_info->pid, &p_info->time,
                            BPF_NOEXIST) == 0)
        __sync_fetch_and_add(&f_state->outstanding_timestamps, 1);
    else
        send_map_full_event(ctx, p_info, PPING_MAP_PACKETTS);
}

/*
 * Calculate a smoothed rtt similar to how TCP stack does it in
 * net/ipv4/tcp_input.c/tcp_rtt_estimator().
 *
 * NOTE: Will cause roundoff errors, but if RTTs > 1000ns errors should be small
 */
static __always_inline __u64 calculate_srtt(__u64 prev_srtt, __u64 rtt)
{
    if (!prev_srtt)
        return rtt;
    // srtt = 7/8*prev_srtt + 1/8*rtt
    return prev_srtt - (prev_srtt >> 3) + (rtt >> 3);
}

/*
 * Attempt to match packet in p_info with a timestamp from flow in f_state
 */
static __always_inline void pping_match_packet(struct flow_state *f_state, void *ctx,
                                               struct packet_info *p_info)
{
    struct rtt_event re = {0};
    __u64 *p_ts;

    if (!is_flowstate_active(f_state) || !p_info->reply_pid_valid)
        return;

    if (f_state->outstanding_timestamps == 0)
        return;

    p_ts = bpf_map_lookup_percpu_elem(&packet_ts, &p_info->reply_pid, bpf_get_smp_processor_id());
    if (!p_ts || p_info->time < *p_ts)
        return;

    re.rtt = p_info->time - *p_ts;

    // Delete timestamp entry as soon as RTT is calculated
    if (bpf_map_delete_elem(&packet_ts, &p_info->reply_pid) == 0)
    {
        __sync_fetch_and_add(&f_state->outstanding_timestamps, -1);
        debug_increment_autodel(PPING_MAP_PACKETTS);
    }

    if (f_state->min_rtt == 0 || re.rtt < f_state->min_rtt)
        f_state->min_rtt = re.rtt;
    f_state->srtt = calculate_srtt(f_state->srtt, re.rtt);

    // Fill event and push to perf-buffer
    /*re.event_type = EVENT_TYPE_RTT;
    re.timestamp = p_info->time;
    re.min_rtt = f_state->min_rtt;
    re.sent_pkts = f_state->sent_pkts;
    re.sent_bytes = f_state->sent_bytes;
    re.rec_pkts = f_state->rec_pkts;
    re.rec_bytes = f_state->rec_bytes;
    re.flow = p_info->pid.flow;
    re.match_on_egress = !p_info->is_ingress;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &re, sizeof(re));*/
    bpf_debug("Send performance event, %u", re.rtt);
}

static __always_inline void close_and_delete_flows(void *ctx, struct packet_info *p_info,
                                                   struct flow_state *fw_flow,
                                                   struct flow_state *rev_flow)
{
    // Forward flow closing
    if (p_info->event_type == FLOW_EVENT_CLOSING ||
        p_info->event_type == FLOW_EVENT_CLOSING_BOTH)
    {
        if (should_notify_closing(fw_flow))
            send_flow_event(ctx, p_info, false);
        fw_flow->conn_state = CONNECTION_STATE_CLOSED;
    }

    // Reverse flow closing
    if (p_info->event_type == FLOW_EVENT_CLOSING_BOTH)
    {
        if (should_notify_closing(rev_flow))
            send_flow_event(ctx, p_info, true);
        rev_flow->conn_state = CONNECTION_STATE_CLOSED;
    }

    // Delete flowstate entry if neither flow is open anymore
    if (!is_flowstate_active(fw_flow) && !is_flowstate_active(rev_flow))
    {
        if (bpf_map_delete_elem(&flow_state,
                                get_dualflow_key_from_packet(p_info)) ==
            0)
            debug_increment_autodel(PPING_MAP_FLOWSTATE);
    }
}

/*
 * Contains the actual pping logic that is applied after a packet has been
 * parsed and deemed to contain some valid identifier.
 * Looks up and updates flowstate (in both directions), tries to save a
 * timestamp of the packet, tries to match packet against previous timestamps,
 * calculates RTTs and pushes messages to userspace as appropriate.
 */
static __always_inline void pping_parsed_packet(void *context, struct packet_info *p_info)
{
    struct dual_flow_state *df_state;
    struct flow_state *fw_flow, *rev_flow;
    bool new_flow = false;

    df_state = lookup_or_create_dualflow_state(context, p_info, &new_flow);
    if (!df_state)
    {
        //bpf_debug("No flow state - stop");
        return;
    }

    fw_flow = get_flowstate_from_packet(df_state, p_info);
    update_forward_flowstate(p_info, fw_flow, &new_flow);
    pping_timestamp_packet(fw_flow, context, p_info, new_flow);

    rev_flow = get_reverse_flowstate_from_packet(df_state, p_info);
    update_reverse_flowstate(context, p_info, rev_flow);
    pping_match_packet(rev_flow, context, p_info);

    close_and_delete_flows(context, p_info, fw_flow, rev_flow);
}

/* Entry poing for running pping in the tc context */
static __always_inline void tc_pping_start(struct parsing_context *context, bool is_wan)
{
    //__u32 cpu = bpf_get_smp_processor_id();
    //bpf_debug("Running on CPU: %u", cpu);

    /* Populate the TCP Header */
    if (context->protocol == ETH_P_IP)
    {
        /* If its not TCP, stop */
        if (context->ip_header.iph->protocol != IPPROTO_TCP)
        {
            return;
        }
        context->tcp = (struct tcphdr *)((char *)context->ip_header.iph + (context->ip_header.iph->ihl * 4));
    }
    else if (context->protocol == ETH_P_IPV6)
    {
        /* If its not TCP, stop */
        if (context->ip_header.ip6h->nexthdr != IPPROTO_TCP)
        {
            return;
        }
        context->tcp = (struct tcphdr *)(context->ip_header.ip6h + 1);
    }
    else
    {
        bpf_debug("UNKNOWN PROTOCOL TYPE");
        return;
    }

    /* Bail out if the packet is incomplete */
    if (context->tcp + 1 > context->data_end)
    {
        return;
    }

    /* Start the parsing process */
    struct packet_info p_info = {0};
    if (parse_packet_identifier(context, &p_info, is_wan) < 0)
    {
        bpf_debug("Unable to parse packet identifier");
        return;
    }

    p_info.is_ingress = false;
    p_info.ingress_ifindex = 0;

    pping_parsed_packet(context, &p_info);
}

#endif /* __TC_CLASSIFY_KERN_PPING_H */