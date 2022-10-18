# cpumap-pping-hackjob

> This is an experiment, please don't rely on it!

The purpose of this project is to merge:

* [XDP-CpuMap-TC](https://github.com/xdp-project/xdp-cpumap-tc)
* [XDP PPing](https://github.com/xdp-project/bpf-examples/tree/master/pping)

Combining these allows me to:

* Remove the parts of `pping` I don't actually need.
    * I have no need for ICMP tracking.
    * DNS tracking isn't a great idea for a lot of ISPs that have a cache setup.
    * I don't care about a lot of data beyond RTT, so things like total size per flow can be removed.
* Combine the efforts of the two, so they aren't each parsing parts of the packet.
* Merge in `tc_handle` to the output, allowing me to provide a pre-classified performance stream.

Currently, it operates just like `xdp-cpumap-tc`---but outputs performance data to the tracing
pipe at `/sys/kernel/debug/tracing/trace_pipe`. This will be turned into a more graceful output.

Once these are working together, the real objective should become possible: [LibreQOS](https://github.com/rchac/LibreQoS)
and [BracketQoS](https://github.com/thebracket/bqos-oss) can stop relying on the (admittedly awesome)
userspace [PPing](https://github.com/pollere/pping) project---because it grinds to a halt faster than
the rest of the setup.

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
{"tc":"1:5", "avg" : 4},
{}]
```

The fields are: `tc`, the customer queue/flow handle, and `avg` the current average RTT in ms.
The dummy entry is present at the end to avoid comma issues.

These are collected on a rolling 60-second ringbuffer, and represent the most recent results.

Run `xdp_pping` periodically (every 30 or 60 seconds, ideally)---it performs map cleanup.