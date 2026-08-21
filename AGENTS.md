# natprobe — working notes

Read this before changing anything under `projects/natprobe`. The user-facing
behaviour is documented in [`README.md`](./README.md); this file is the part
that is not obvious from the code: why the network code is shaped the way it
is, what can actually be tested, and what will hang or silently lie if you
change it.

## What it is, and when you reach for it

A Go CLI that asks the LAN gateway three separate questions — do you speak
NAT-PMP, PCP, UPnP IGD? — and reports each answer independently. You reach for
it when a port-forwarding client (in practice `namefi-dyndns`) fails on
someone's router and you need to know *which* layer failed: no protocol at all,
a protocol that answers but refuses, a mapping that succeeds but is unreachable
because the ISP is doing CGNAT.

The design inversion versus a production client is the whole point and it
recurs everywhere in this code:

| | production (`namefi-dyndns`) | natprobe |
|---|---|---|
| protocol selection | first that works wins | all three, always, concurrently |
| remapped external port | failure, rolled back (`ErrPortRemapped`) | reported as `supported`, lease kept |
| lease lifetime | 2h, renewed at half-life | 120s, deleted on exit |
| wire detail | logged sparsely | full transcript, retained per probe |

If you find yourself "fixing" natprobe to behave like the production client,
you are removing the feature.

## Layout

```
natprobe/
├── cmd/natprobe/main.go     13 lines: os.Exit(cli.Run())
└── internal/
    ├── cli/                 cobra wiring only, no protocol logic
    │   ├── root.go          shared flags, signal ctx, exitError plumbing,
    │   │                    trace rendering
    │   ├── gateway.go       route-table discovery + raw 5351/1900 liveness
    │   ├── check.go         verdict table, CGNAT/double-NAT/echo prose
    │   ├── mapcmd.go        map/unmap, deferred cleanup, privileged guard
    │   └── upnpcmd.go       upnp describe
    └── probe/               everything that touches the wire
        ├── spec.go          port spec parsing, Privileged()
        ├── probe.go         Verdict/Classify, sentinel errors, Gateway
        │                    discovery, CGNAT & RFC1918 tests, UDPProbe
        ├── trace.go         Trace (mutex-guarded), HexDump
        ├── lease.go         Lease, Remapped()
        ├── natpmp.go        NAT-PMP + the shared udpRoundTrip
        ├── pcp.go           PCP (uses natpmp.go's udpRoundTrip and port var)
        ├── upnp.go          SSDP, description XML, SOAP, mapping-table dump
        ├── check.go         concurrent all-protocol Check → CheckReport
        └── mapop.go         MapProtocol/UnmapProtocol, Verify
```

The dependency direction is strict: `cli` imports `probe`, never the reverse,
and `cli` contains no packet or HTTP construction. Keep it that way — the
tests for protocol behaviour all live in `probe` and rely on being able to
drive it without cobra.

## Per-protocol notes

### NAT-PMP (RFC 6886)

Two-byte request `{version=0, opcode=0}` gets you the gateway's external
address; that is the entire liveness probe and it is a read, so it is safe to
fire at a stranger's router. Responses are fixed-size big-endian: 12 bytes for
external-address, 16 for a map. `natpmpResultText` covers §3.5 codes 0-5, and
code 2 ("not authorized") is the common real-world answer from a router where
port mapping is switched off in the admin UI — it is an *answer*, so it
classifies as `unsupported`, not `timeout`.

Delete is a map request with **external port and lifetime both zero**
(`NATPMPUnmap`). The internal port is what identifies the mapping. Do not
"clean up" that function by filling in the external port.

NAT-PMP gives you the granted port but not the external address in the same
reply, so `NATPMPMap` issues a second external-address query afterwards. If
that second call fails the lease is still returned, with an invalid address and
a valid port. Callers must tolerate `Lease.External.Addr()` being invalid;
`renderExternal` prints `?:port` for exactly that case.

### PCP (RFC 6887)

Shares UDP port 5351 with NAT-PMP, and that collision is load-bearing in two
places:

- `pcp.go` has no port constant of its own; it uses `natpmpPort` from
  `natpmp.go`. One var, one place tests swap.
- A NAT-PMP-only gateway answers a PCP request with a **version-0** NAT-PMP
  "unsupported version" error. `PCPAnnounce` checks `resp[0] == 0` and reports
  "gateway answered with NAT-PMP version 0 (PCP not spoken)". Without that
  check you would read a NAT-PMP error packet as a malformed PCP header and
  produce a confusing verdict.

PCP requires the client's own address in the request header (bytes 8:24, as a
v4-mapped v6 `As16()`). `PCPMap` refuses with `ErrUnsupported` when `self` is
invalid rather than sending zeros, because a gateway would answer result 12
(address mismatch) and the real cause — we never found our own LAN address —
would be hidden.

The MAP request carries a 12-byte random nonce (bytes 24:36) and the response
is rejected if the nonce does not match. On a shared UDP port with a router
that may also be answering NAT-PMP, that check is what proves the reply is
ours.

The suggested external address is sent as all-zeros (`IPv4Unspecified`): let
the gateway choose its own external address, but keep our requested port.

Delete is `PCPMap` with lifetime 0. That same zero-lifetime call is also used
in `check.go` as a *read*: it reveals the external address the gateway would
assign without creating anything. Note the consequence in `PCPMap` — the
remap check is guarded by `lifetime > 0`, so a probe/delete is never reported
as a remap.

### UPnP IGD

Discovery is a **unicast** M-SEARCH sent straight to the gateway on 1900/udp,
not a multicast one. The `HOST` header still names `239.255.255.250:1900`
because the spec requires it, but nothing is sent to that address. The reason:
we already know the gateway from the route table, and multicast is routinely
eaten by host firewalls, so multicast discovery fails in ways that look like
"the router does not support UPnP". If you switch this to real multicast you
will reintroduce false negatives.

Parsing quirks that real routers force:

- The SSDP response is scanned with `strings.Cut(line, ":")` — split on the
  **first** colon only, because the `LOCATION` value is a URL containing its
  own colons.
- Device descriptions nest recursively (`InternetGatewayDevice` →
  `WANDevice` → `WANConnectionDevice`), and services can hang off any level,
  so `fetchDescription` walks the whole tree and collects every service, then
  picks the first match from `wanServices` (`WANIPConnection:2`, then `:1`,
  then `WANPPPConnection:1` for older DSL gear). A device with none of them
  cannot port-map at all, and that is reported as `unsupported` with that
  wording.
- Control URLs are relative on most routers, so they are resolved against
  `URLBase` when the description supplies one, otherwise against the
  `LOCATION` URL.
- Both HTTP reads are capped (`256<<10` for the description, `64<<10` for
  SOAP) so a broken device cannot make natprobe read forever.

`ListPortMappings` enumerates by index and stops on **UPnP error 713**
(`SpecifiedArrayIndexInvalid`) — that is how IGD signals end-of-list; there is
no count. The detection is `strings.Contains(err.Error(), "713")`, which is
fragile by nature: it depends on `soapFaultString` keeping the numeric code in
the message. If you reword that error string, the enumeration silently runs to
its 1000-iteration cap and issues 1000 SOAP calls to the router. The cap
exists precisely because that failure mode is plausible.

Unlike PCP/NAT-PMP, UPnP grants the exact requested external port or fails
(error 718 `ConflictInMappingEntry`), so there is no remap path here.

## Key decisions a newcomer would get wrong

**No retransmit loop.** `udpRoundTrip` sends one datagram and reads one reply.
The RFCs prescribe exponential retransmission because they assume a client that
must succeed; natprobe's job is to *report* "nothing answered within the
timeout", so retrying would only blur the RTT and the verdict. If you add
retries, `Result.RTT` stops meaning what the table says it means.

**"Connection refused" is a timeout, not an error.** A UDP read can fail with
ICMP port-unreachable when the gateway is alive but nothing listens on 5351.
`udpRoundTrip` maps that to `ErrTimeout` with "(nothing listening on N/udp)".
The taxonomy is deliberate: `VerdictError` means *we* broke, not the router.
See `Classify` — and note `ErrPortRemapped` classifies as `unsupported` there
(the gateway did speak), which `mapop.go` then upgrades to `supported` for the
map command, because for a diagnostic a remap is proof the protocol works.

**Timeouts are per-attempt, not per-run.** `--timeout` (default 3s) bounds one
exchange. `check` runs the three protocols concurrently so the wall-clock cost
of a dead gateway stays around one timeout, not three.

**Cleanup must survive Ctrl-C.** `root.go` builds the command context from
`signal.NotifyContext`, so SIGINT cancels the probe. The deferred cleanup in
`mapcmd.go` therefore cannot use that context — it creates a *fresh*
`context.Background()` with the timeout. If you swap that back to `cmd.Context()`
every interrupt will leave a live mapping on the user's router.

**Cleanup deletes the granted port, not the requested one.** The deferred loop
overrides `cleanupSpec.External` from `a.Lease.External.Port()`. After a remap
those differ, and deleting the requested port would leave the real mapping
behind.

**Short lifetime is the safety net.** `--lifetime` defaults to 120s so that
even if the process is SIGKILLed, the leftover expires quickly. Raising the
default weakens the only guarantee that survives a hard kill.

**Ports below 1024 are refused** without `--allow-privileged`, because
`AddPortMapping` on a well-known port can overwrite a forwarding entry someone
depends on. The refusal message names the flag; `cli_test.go` asserts that.

**`--verify` failing does not mean the mapping failed.** It connects to the
external ip:port from *inside* the LAN, which needs hairpin NAT. `VerifyResult`
carries `Hairpin: true` and every failure message says so. Do not simplify that
wording into "mapping is broken".

**`--echo` is the only outbound internet request in the tool**, and it is
off by default. Everything else stays on the LAN.

## Relationship to namefi-dyndns

Verified: the wire-format code is adapted from
`projects/namefi-dyndns/internal/portmap`, which implements the same three
protocols for real. The lineage is visible in shared shapes — the `Lease`
struct, the `natpmpPort` / `ssdpPort` test-swappable vars with near-identical
comments, the same `wanServices` preference order, the same `ErrPortRemapped`
sentinel text. It is a copy, not an import: `internal/` cannot cross Go module
boundaries and these are two separate modules.

Divergences that are real and intentional:

- dyndns's `Mapper` interface returns `ErrPortRemapped` as a hard failure
  (request-or-nothing: dyndns publishes a hostname without a port, so a remap
  means the name no longer reaches the service). natprobe keeps the lease.
- dyndns has `ErrNoGateway`; natprobe has `ErrTimeout` in that role, plus
  `Verdict`/`Classify`, which dyndns has no need for.
- dyndns renews at half-lifetime (`Lease.RenewAt`) and requests 2h. natprobe
  has no renewal at all — it never holds a mapping long enough to need one.

Smaller divergence worth knowing if you diff them: dyndns's PCP dials `"udp"`
while natprobe dials `"udp4"` throughout (`udpRoundTrip` is v4-only). natprobe
is IPv4-only by construction — `IsCGNATv4`/`IsPrivateV4` return false for v6,
and `NATPMPExternal` parses a 4-byte address. Adding IPv6 is a real change,
not a tweak.

If a third consumer ever appears, the shared wire formats belong in a common Go
module rather than a third copy.

## Build and test

Verified working in this repo (`GOTOOLCHAIN=local` is required here):

```console
$ cd projects/natprobe
$ GOTOOLCHAIN=local go build -o /tmp/natprobe ./cmd/natprobe
$ GOTOOLCHAIN=local go test ./...          # 43 tests, ~5s
$ GOTOOLCHAIN=local go test ./... -race    # clean
$ GOTOOLCHAIN=local go vet ./...
$ gofmt -l .                               # must print nothing
$ GOTOOLCHAIN=local go run ./cmd/natprobe --help
```

`cmd/natprobe` has no test files; that is expected, `main` is three lines.

## Testing reality

**Everything in the test suite runs against local fakes. No test touches a
real network, and none should.**

- `natpmp_test.go` / `pcp_test.go` start a UDP listener on an ephemeral
  127.0.0.1 port and hand-assemble replies (including refusal result codes and
  simulated remaps via `grantPort`).
- `upnp_test.go` uses an `httptest.Server` for the description and SOAP control
  endpoint, plus a UDP responder that returns a `LOCATION` pointing at it.
- Redirection works by **mutating the package-level `natpmpPort` / `ssdpPort`
  vars** (`swapNATPMPPort`, `swapSSDPPort`, both restoring via `t.Cleanup`).
  Consequences: those vars must stay package-level `var`, not `const`; and no
  test in `probe` may call `t.Parallel()` while relying on them. None does
  today. If you add a parallel test that swaps a port, you will get
  cross-test flakes that look like router weirdness.
- Timeout paths are tested by pointing the port var at `1` (nothing listens)
  with a short timeout.
- `check_test.go` pins the `check --json` and `map --json` top-level key sets as
  string goldens, because the schema is documented in the README. A field
  rename breaks these on purpose.

What the fakes cannot cover, and where you genuinely need a real router on a
real LAN:

- `DiscoverGateway` (route table via `tailscale.com/net/netmon`) and
  `interfaceFor`. No test exercises them.
- Real vendor SSDP/description quirks: absent `URLBase`, odd nesting, vendors
  that answer M-SEARCH but serve an unfetchable `LOCATION`.
- End-of-list behaviour of `GetGenericPortMappingEntry` on actual firmware, and
  the 713 string match.
- `Verify` / hairpin NAT, CGNAT detection against a real ISP, and `--echo`.
- Whether a router silently remaps, and whether a delete actually removes the
  entry.

There is no opt-in live test here. `namefi-dyndns` has one
(`internal/portmap/live_probe_test.go`, gated on `PORTMAP_LIVE_PROBE=1`,
read-only); natprobe's equivalent is simply running the binary. If you add a
live test, gate it behind an env var and keep it read-only, matching that
pattern — and note that `natprobe map` against a real router *writes* to it.

## Invariants

- `probe` never imports `cli`; `cli` never builds packets.
- `natpmpPort` and `ssdpPort` stay mutable package vars (tests depend on it),
  and PCP keeps using `natpmpPort` rather than defining its own.
- `Trace` is used concurrently by `Check`'s three goroutines-worth of protocol
  code; its mutex and the nil-receiver guards in `add`/`Entries` must stay.
- `Classify`'s mapping is the exit-code contract: `check` returns 0 iff at
  least one verdict is `supported` (`AnySupported`), 1 for none, 2 for config
  errors. `cli_test.go` covers the config-error cases.
- The documented JSON keys are golden-pinned; change README and goldens
  together.
- Deferred map cleanup uses a fresh context and the granted port.

## Loose ends found while reading

- `gateway.go` passes the literal ports `5351` and `1900` to `probe.UDPProbe`
  instead of the `probe` package's port vars (which are unexported anyway), so
  the `gateway` command cannot be pointed at a fake. That is why there is no
  test for it.
- The 713 end-of-list detection via substring match on the error text is the
  most brittle thing in the codebase (see above). Worth hardening to a typed
  fault code if anyone touches `soap`.
- `renderAddr` in `gateway.go` detects an invalid address by comparing against
  the literal string `"invalid IP"`, i.e. it depends on `netip.Addr.String()`'s
  output for the zero value. `Self.IsValid()` would be the robust check.
