# cpumap-pping

This project combines [XDP-CpuMap-TC](https://github.com/xdp-project/xdp-cpumap-tc) and [XDP PPing](https://github.com/xdp-project/bpf-examples/tree/master/pping), allowing a Linux traffic-shaping server to simultaneously shunt classifiers to multiple CPU cores and provide Quality-of-Experience (QoE) metrics based on TCP round-trip-times. The project is used by [LibreQOS](https://github.com/rchac/LibreQoS) and [BracketQoS](https://github.com/thebracket/bqos-oss).

## Rationale

Linux traffic shaping with `tc` is often limited to processing packets on a single core. That's fine for many requirements, but struggles when applied to a large network. LibreQoS and BracketQoS both seek to provide Cake-based shaping (along with queue trees) to ISP-scale networks, requiring the classification load be spread across multiple cores.

[XDP-CpuMap-TC](https://github.com/xdp-project/xdp-cpumap-tc) solves this problem by allowing users to create classification queues per CPU. IP addresses (including subnets and IPv6 now my Trie patch is live) are allocated to
classifier handles (major:minor now following the CPU:queue format). An XDP program reads IP addresses from each packet
on ingress, and "shunts" the packet to the correct CPU for processing. In turn, the classifier eBPF program looks up the
correct entry-point in the CPU's queue tree and processes the outgoing packet accordingly. This has been very successful
in scaling inline traffic shapers far beyond what could be reasonably accomplished on a single core.

Previous versions gathered QoE data with [pping](https://github.com/pollere/pping), Kathleen Nichol's (of Pollere, Inc.)'s
fantastic userspace tool. It does a great job, but runs into scaling issues when monitoring large volumes of traffic. Monitoring TCP round-trip-times while shaping several gigabits-per-second of real-time traffic would heavily load a single CPU core---leading some users to disable QoE tracking.

Simon Sundberg created [XDP PPing](https://github.com/xdp-project/bpf-examples/tree/master/pping), an XDP-based TCP RTT tracket, inspired by [pping](https://github.com/pollere/pping). It gathers data in XDP-space (fast in-kernel VM) rather than through packet sniffing---and can handle large volumes of traffic, while providing very similar output to pping. It works wonderfully for gathering TCP RTT data.

Unfortunately:

* Chaining XDP programs together is a convoluted process. You can use `bpftool` to daisy-chain multiple XDP programs, and classifier programs can chain one another---but once you include necessary setup for each tool, it becomes a painful task.
* When chained together, `xdp-cpumap-tc` and `xdp pping` work---but looking at the code shows a large amount of overlap. Each program is independently parsing Ethernet, IP and TCP headers. Worse, `xdp-cpumap-tc` includes some additional logic to handle VLAN headers---but `xdp pping` doesn't. So the results in some environments were inconsistent.

This project was born to merge the two. Most of `tc_classify_kern_pping.h` is Sunberg's `xdp pping` program, while the rest is the `xdp-cpumap-tc` system (forked after my addition of CIDR and IPv6 patch was accepted). Packet processing is combined into a single `packet-context` type, and both programs modified to use it---ensuring that packet decoding logic is shared along the chain. `xdp pping` was slightly modified to run as part of the classifier (rather than the XDP ingress portion), with maps "pinned" to share data between egress classifiers on two different interfaces. Output was modified to match the requirements of LibreQoS.

Early testing results show that there is very little overhead to gathering TCP RTT data in this way. Overall performance has been within 1% (CPU load) of using regular `xdp-cpumap-tc` without QoE gathering.

## What I'm not trying to do (yet)

I'm not trying to save the world, just help the projects I'm directly involved in:

*  A unified system for chaining these systems and not duplicating data would be awesome, but is outside of my current scope.
* I don't really want to create a nifty plugin system, yet. With the size limits of BPF programs, I'm not even sure if that's possible.

## Usage

1. Setup as normal for `xdp-cpumap-tc`. This is baked into LibreQoS and BracketQoS.
2. Once running, you can run `src/xdp_pping` at any time to see current performance statistics in JSON format.

For example:

```json
[
{"tc":"1:5", "avg": 2.64, "min": 0.38, "max": 2.39, "samples": 12},
{}]
```

The fields are:

* `tc` : the TC flow handle
* `avg`: the average round-trip time (RTT) in ms.
* `min`: the minimum round-trip-time (RTT) in ms.
* `max`: the maximum round-trip-time (RTT) in ms.
* `samples`: the number of samples collected since the last execution.

These are collected on a rolling 60-second ringbuffer, and represent the most recent results.

Run `xdp_pping` periodically (every 30 or 60 seconds, ideally)---it performs map cleanup.

## Copyrights and Licensing

It's always a little complicated to ensure that everyone's copyrights are announced correctly, and licenses specified.

* [xdp-cpumap-tc](https://github.com/xdp-project/xdp-cpumap-tc) doesn't include a copy of the GPL, but tags all programs as "GPL". One script explicitly states that it is GPL 2. Therefore, the project is reasonably assumed to be GPL2.
* [bpf-examples](https://github.com/xdp-project/bpf-examples) also doesn't include a license, but also tags all programs as "GPL". Therefore, it is assumed to be GPL2.
* [pping](https://github.com/pollere/pping) is GPL2.
* This project is GPL2.

My modifications to the included projects are: Copyright (c) 2002, Herbert Wolverson (Bracket Productions). `XDP-cpumap-tc` and `bpf-examples` don't include an explicit copyright statement, and remained copyrighted to their respective authors. `pping` remains Copyright (C) 2017 Kathleen Nichols, Pollere, Inc.
