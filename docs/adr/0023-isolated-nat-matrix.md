# ADR 0023: Isolated NAT, CGNAT, and IPv6 matrix

## Status

Accepted. The harness creates and exercises a real, local Linux namespace
topology. It is laboratory evidence, not a claim about a consumer router,
carrier network, public rendezvous service, TURN service, or Internet success
rate.

## Decision

`scripts/nat_netns_matrix.py` is the sole entrypoint for this matrix. `run`
does not call `ip`, `nft`, or `nsenter` in the invoking network namespace. It
first creates a fresh user/mount/network/PID namespace with `unshare`; only the
internal PID-1 executor performs network setup.

Before any `ip`, `nft`, or `nsenter` call, the executor itself invokes
`unshare(CLONE_NEWNET)`. It refuses to run unless all of these hold:

- it is UID 0 inside the mapped user namespace; and
- it is PID 1 inside the new PID namespace; and
- its `/proc/self/ns/net` inode changes across its own `unshare` syscall.

This is a causal safety boundary rather than caller-supplied provenance. Even a
direct invocation of the hidden executor either fails before mutation or first
creates the namespace where all mutations occur. The public runner additionally
verifies that the host, outer, and executor network-namespace inodes are all
distinct before accepting the artifact.

Each endpoint is a separate `unshare --net` process. The executor creates
deterministically named `ld*` veth pairs, moves their peer into the child PID's
network namespace, and configures the resulting client, server, and observer
nodes. The outer isolated namespace is the single-router profile's router.
Double-NAT and CGNAT use three isolated L2 bridges and **two separate router
processes**, each with its own forwarding and nftables NAT/filter table.

The fixed profiles are intentionally expressed in the mapping and filtering
terms of RFC 4787 rather than ambiguous “cone” labels:

| Profile | Actual topology and required observation |
| --- | --- |
| `lan-v4` | Client, outer router, and server namespaces exchange a non-loopback IPv4 UDP echo. |
| `native-v6` | The equivalent ULA IPv6 namespaces exchange a non-loopback UDP echo. |
| `udp-blocked` | An isolated nftables `input` and `forward` UDP drop prevents the echo; a timeout is the expected observation. |
| `broken-v6` | An isolated exact IPv6 blackhole route prevents the echo; a timeout is the expected observation. |
| `eim-eif` | The server and observer see the same translated tuple; alternate observer port and alternate observer address both reach the client. |
| `eim-adf` | The translated tuple is stable; same observer address/different port reaches the client, while an alternate observer address is dropped. |
| `eim-apdf` | The translated tuple is stable; alternate observer port and address are both dropped. |
| `apdm-mapping` | RFC 4787 address-and-port-dependent mapping: same client source is translated to distinct tuples for server and a same-address alternate-port destination; the observer cannot use the server's public mapping. |
| `double-nat` | Two child routers translate the client over an intermediate private link before a public test LAN echo. |
| `cgnat` | The same two-router topology records the actual path `10.77/16 → 100.64/10 → 198.18/15` and requires the public echo. |

Every NAT profile receives disjoint deterministic addressing. This matters:
conntrack state belongs to the outer router namespace and can outlive a veth;
reusing a five-tuple could otherwise turn an old translation into false
evidence for the next profile.

## Evidence contract

Each result records its expected and observed outcomes, setup/probe/cleanup
argv, SHA-256 hashes for each command group and all commands, and a hash of
captured stderr. A result is `pass` only when every required observation
matches the profile contract. Kernel/tooling unavailability is `blocked`;
mismatching packet behavior is `failed`; the harness does not default to
`skip` when `--allow-netns` is requested. `nat64` is explicitly `optional`
because it needs a supplied gateway rather than an invented approximation.

Cleanup is part of the assertion: nft tables, public loopback addresses,
veths, bridges, workloads, and child namespace processes are removed/reaped in
`finally`. Commands only target names created by the profile, and the outer
namespace is destroyed when the executor exits.

Run the minimal mandatory smoke matrix with:

```text
python3 scripts/nat_netns_matrix.py run --allow-netns \
  --profiles lan-v4 native-v6 udp-blocked broken-v6 \
  --output artifacts/nat-matrix.json
```

Run all fixed profiles with `--profiles` omitted. The JSON artifact, rather
than process output, is the reviewable result.

## Consequences and limits

This demonstrates that the client-side route-selection work can be exercised
against repeatable emulated mapping/filtering behavior without mutating the
host network namespace. It does **not** measure a real NAT appliance,
hairpinning, NAT64, captive portal, DNS, public relay availability, carrier
rate limits, MTU loss, IPv6 deployment, ICE nomination/consent, or desktop
latency. A physical/inter-network matrix remains required before advertising
NAT traversal reliability or superiority over another remote-desktop product.

RFC 4787 separates mapping behavior from filtering behavior; the observer
probes deliberately test both rather than inferring one from the other. Linux
network namespaces isolate network devices, protocol stacks, routing tables,
firewall rules, and sockets, which is why the harness requires the self-created
namespace and distinct-inode gates. nftables NAT chains are configured only inside those
isolated namespaces.

Sources:

- [RFC 4787, UDP NAT behavioral requirements](https://www.rfc-editor.org/rfc/rfc4787.html)
- [Linux `network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [nftables NAT documentation](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT))
