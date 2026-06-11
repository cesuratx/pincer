---
name: pcap-analysis
description: Analyze a pcap/pcapng capture with pincer and report findings — flows, assets, services, dependencies, and anomalies. Use when the user hands over a capture file and asks what's in it, who's talking to whom, what devices are present, or to investigate suspicious traffic.
---

# pcap-analysis — triage a capture with pincer

A repeatable workflow for turning a capture into a clear findings report. Build
first (`cargo build`) if needed, then drive the CLI.

## Triage order

Run these in sequence; each answers a question the next builds on.

1. **Shape of the capture** — `cargo run -- summary <file>`
   - Packet/byte totals, time span, protocol mix.
   - Check the **anomalies** line. Non-zero `malformed`/`truncated`/`undecodable`
     means the capture is partial, hostile, or not Ethernet — note it; don't
     hide it.

2. **Who talks to whom** — `cargo run -- flows <file>`
   - Bidirectional flows sorted by bytes. Top talkers, unexpected ports,
     one-sided flows (SYN with no SYN-ACK = unanswered / scan).
   - The `name` column is TLS SNI / HTTP Host when known.

3. **What devices are present** — `cargo run -- assets <file>`
   - Per-host inventory: MAC (local) or IP (off-link), hostnames with source,
     DHCP fingerprint, vendor class. Cross-reference fingerprints to guess OS.

4. **What each host serves** — `cargo run -- services <file>`
   - Listening services with evidence strength: `SynAck` (proven listening)
     > `AppLayer` (banner seen) > `PortHeuristic` (port number only).

5. **Application dependency map** — `cargo run -- deps <file>`
   - client → server:port edges with byte volumes. `--dot` pipes to Graphviz
     (`cargo run -- deps --dot <file> | dot -Tpng -o deps.png`).

6. **Naming detail when needed** — `cargo run -- dns <file>` and `dhcp <file>`.

Use `--json` on any subcommand to extract structured data for further work.

## Writing up findings

Lead with the answer to what was asked. Then support it:
- State the network shape in one line (host count, time span, dominant protocols).
- Call out anything anomalous: unanswered SYNs, scans (one host hitting many
  ports), plaintext credentials/hosts, unexpected external destinations,
  high-volume flows to unknown IPs.
- Attribute every claim to its evidence (e.g. "listening — SYN-ACK observed",
  "name from DHCP option 12", "service inferred from port only, unconfirmed").
  This evidence discipline is the whole point of passive discovery — never
  assert more confidence than the packets support.
- Note capture limitations that affect conclusions (snaplen truncation, no TCP
  reassembly so a split TLS ClientHello shows no SNI).
