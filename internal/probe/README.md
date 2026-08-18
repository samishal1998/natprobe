# internal/probe

Protocol implementations and diagnostic primitives for natprobe. Wire-format
code adapted from `projects/namefi-dyndns/internal/portmap` (see the root
README for the lineage and consolidation note).

```
probe/
├── spec.go        # Spec (port/proto) parsing, privileged-port guard; package doc
├── probe.go       # Verdict taxonomy, sentinel errors, Result, gateway discovery,
│                  # CGNAT / double-NAT classification, raw UDP "is anyone home" probe
├── trace.go       # Trace transcripts + the annotated HexDump formatter
├── lease.go       # Lease (granted mapping) + remap detection
├── natpmp.go      # NAT-PMP (RFC 6886): external-address, map, delete
├── pcp.go         # PCP (RFC 6887): ANNOUNCE, MAP, delete; result-code texts
├── upnp.go        # UPnP IGD: SSDP discovery, description parse, SOAP actions,
│                  # GetGenericPortMappingEntry enumeration
├── check.go       # Concurrent all-protocol check + CheckReport (--json schema)
├── mapop.go       # Per-protocol map/unmap orchestration + --verify listener
└── *_test.go      # Fake gateways (UDP NAT-PMP/PCP, httptest IGD + SSDP responder)
                   # and unit tests incl. JSON schema goldens
```

How the pieces relate: the protocol files (`natpmp.go`, `pcp.go`, `upnp.go`)
each expose raw operations that take a `*Trace` and return leases/errors
classified by the sentinel errors in `probe.go`. `check.go` runs all three
concurrently and aggregates into a `CheckReport`; `mapop.go` runs a real
mapping per protocol and keeps remapped grants for cleanup instead of rolling
them back (the diagnostic inversion of the production policy).

Tests never touch the real network: `natpmpPort` / `ssdpPort` are swapped to
localhost fakes per test.
