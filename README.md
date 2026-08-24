# natprobe

`natprobe` is `dig` for NAT traversal: a standalone diagnostic CLI that probes
the LAN gateway for **UPnP IGD**, **PCP** (RFC 6887), and **NAT-PMP**
(RFC 6886) support, shows wire-level detail, and explains failures in plain
language.

Where a production port-mapping client stops at the first protocol that
works, natprobe tries **all three to completion**, times each exchange,
decodes every packet, and tells you *why* the ones that failed failed.

## Install

macOS / Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/samishal1998/natprobe/main/install.sh | sh
```

The installer picks the right build for your platform, verifies it against the
published `checksums.txt`, and installs into `~/.local/bin` (or the first
writable directory already on your `PATH`). Two knobs:

```sh
NATPROBE_VERSION=v0.1.0 sh install.sh      # pin a version
NATPROBE_INSTALL_DIR=/usr/local/bin sh install.sh
```

With Go, or on Windows (where the installer does not apply, download the
`.zip` from [Releases](https://github.com/samishal1998/natprobe/releases)):

```sh
go install github.com/samishal1998/natprobe/cmd/natprobe@latest
```

## Quickstart

```console
$ natprobe check
```

From a source checkout:

```console
$ go build -o natprobe ./cmd/natprobe
$ ./natprobe check
```

## Commands

### `natprobe gateway`

Discovers the LAN gateway and your own address from the OS route table (via
`tailscale.com/net/netmon`, the same mechanism namefi-dyndns uses), and checks
whether anything answers on the two NAT traversal ports.

```console
$ natprobe gateway
Gateway:    192.168.1.1
Own addr:   192.168.1.11
Interface:  en0
5351/udp:   ✗ no answer — NAT-PMP/PCP disabled or not supported
1900/udp:   ✓ SSDP port answered
```

### `natprobe check`

The headline command: probes all three protocols **concurrently** and prints a
verdict table.

```console
$ natprobe check
Gateway 192.168.1.1 (checked 2026-08-18T02:22:31Z)

PROTOCOL  VERDICT       RTT       EXTERNAL          DETAIL
nat-pmp   timeout       3ms       -                 gateway did not answer on 5351/udp — NAT-PMP disabled or not supported
pcp       timeout       3ms       -                 gateway did not answer on 5351/udp — PCP disabled or not supported
upnp      supported     14ms      197.58.165.154    IGD discovered, GetExternalIPAddress answered
                                                    server: Linux UPnP/1.0 Huawei-ATP-IGD; Huawei Home Gateway; HG630 V2

Gateway-reported external address: 197.58.165.154
```

The external address is read the cheapest way each protocol allows: the
NAT-PMP external-address op, a PCP ANNOUNCE plus a 0-lifetime MAP probe, and
UPnP `GetExternalIPAddress`.

Cross-protocol analysis:

- **CGNAT detection** — an external address in `100.64.0.0/10` (RFC 6598)
  means your ISP shares one public address across customers; a port mapping on
  this router cannot make you reachable from the internet. Said plainly in the
  output.
- **Double NAT** — an RFC 1918 external address means this router itself sits
  behind another NAT.
- **`--echo`** (off by default, sends one outbound HTTPS request) — compares
  the gateway-reported external address against a public what-is-my-ip
  endpoint; a mismatch means traffic is NATed again beyond this router.

Exit codes: `0` if **any** protocol works, `1` if none, `2` for configuration
errors (bad flags, no gateway found).

### `natprobe map --port 8080/tcp`

Requests a **real** mapping and reports what each protocol granted:

```console
$ natprobe map --port 18099/tcp
pcp:     timeout — gateway did not answer — pcp disabled or not supported
nat-pmp: timeout — gateway did not answer — nat-pmp disabled or not supported
upnp:    supported — external 197.58.165.154:18099, lifetime 2m0s
Deleted the upnp mapping.
```

- `--lifetime` defaults to **120s** so leftovers expire fast even if cleanup
  never runs.
- The mapping is **deleted before exit** (including on Ctrl-C) unless you pass
  `--keep`.
- `--protocol auto|pcp|natpmp|upnp` selects protocols (`auto` tries all).
- A grant on a **different** port than requested is reported as a remap
  ("router granted a different port (61000): treat as remap") — still proof
  the protocol works.
- `--verify` starts a temporary listener on the internal port and attempts a
  TCP connect / UDP echo through the granted external ip:port. When run from
  inside the LAN a failure can mean the router lacks **hairpin NAT** rather
  than a broken mapping; the output says so.
- Ports below 1024 are refused without `--allow-privileged` (probing
  well-known ports risks clobbering a real forwarding entry).
- Port spec forms: `8080/tcp`, `8443:8081/tcp` (external:internal), `5353/udp`.

### `natprobe unmap --port 8080/tcp`

Best-effort delete on all three protocols, for cleaning up after `--keep` or a
killed run.

### `natprobe upnp describe`

Dumps the IGD device description and — the real differentiator for debugging —
the router's **existing port-mapping table** via `GetGenericPortMappingEntry`
enumeration (until UPnP error 713, end of list):

```console
$ natprobe upnp describe
SSDP LOCATION:  http://192.168.1.1:37215/upnpdev.xml
SSDP SERVER:    Linux UPnP/1.0 Huawei-ATP-IGD
Friendly name:  Huawei Home Gateway
Manufacturer:   Huawei Technologies Co., Ltd.
Model:          HG630 V2

Services:
  * urn:schemas-upnp-org:service:WANPPPConnection:1
      control: http://192.168.1.1:37215/ctrlu/WANPPPConnection_1
  ...
  (* = service used for port mapping)

Existing port mappings (2):
  EXT     PROTO  INTERNAL               ENABLED  LEASE     DESCRIPTION
  24381   UDP    192.168.1.11:41641     yes      static    tailscale-portmap
  7725    UDP    192.168.1.11:41641     yes      static    tailscale-portmap
```

## Cross-cutting flags

| Flag | Meaning |
|---|---|
| `-v, --verbose` | Wire-level transcripts: annotated hex dumps for NAT-PMP/PCP (e.g. `opcode=0x81 result=0 epoch=12345`), full HTTP/SOAP exchanges for UPnP |
| `--json` | Machine-readable output on `gateway`, `check`, `map` (schema below) |
| `--gateway <ip>` | Probe a specific gateway instead of the route-table one |
| `--timeout` | Per-attempt timeout, default 3s |

## How to read the verdicts

| Verdict | Meaning |
|---|---|
| `supported` | The gateway answered and honored the operation. |
| `unsupported` | The gateway **answered** but refused (an explicit error code, a NAT-PMP-only reply to PCP, no WAN service in the description). The protocol stack is there; the operation isn't allowed. |
| `timeout` | Nothing answered on the protocol's port. The likely cause is named (disabled or not supported). |
| `error` | A local problem (socket failure) prevented the probe. |

## JSON schema

Stable top-level keys (pinned by golden tests; durations are nanoseconds
unless the key says otherwise, timestamps are ISO 8601):

`check --json`:

```json
{
  "checked_at": "2026-01-02T03:04:05Z",
  "gateway": {"gateway": "192.168.1.1", "self": "192.168.1.50", "interface": "en0"},
  "results": [
    {
      "protocol": "nat-pmp | pcp | upnp",
      "verdict": "supported | unsupported | timeout | error",
      "rtt_ns": 2000000,
      "external": "203.0.113.7",
      "server": "vendor/version info when available",
      "detail": "plain-language explanation",
      "trace": [{"at": "...", "dir": "send|recv|note", "label": "...", "detail": "..."}]
    }
  ],
  "external": "203.0.113.7",
  "cgnat": false,
  "double_nat": false,
  "echo_address": "(only with --echo)",
  "echo_mismatch": false
}
```

`map --json`: `{"mapped_at", "gateway", "spec", "lifetime_seconds", "attempts": [{"protocol", "verdict", "external", "lifetime_seconds", "remapped", "detail", "trace"}], "kept", "verify"}`.

`gateway --json`: `{"checked_at", "gateway", "self", "interface", "answers_5351_udp", "answers_1900_udp"}`.

## Relationship to namefi-dyndns

The wire-format code (NAT-PMP/PCP packet layouts, SSDP discovery, IGD SOAP)
is adapted from `projects/namefi-dyndns/internal/portmap`, which implements the
same three protocols for production use (first-protocol-wins, leases renewed at
half-lifetime, request-or-nothing on remaps). natprobe inverts those choices
for diagnosis: all protocols tried, remaps reported instead of rolled back,
transcripts recorded. `internal/` packages cannot be imported across Go
modules, so the code is copied and adapted; if a third consumer appears, a
shared `projects/pkg/` (or a `packages/`-style Go module) for the wire formats
is the natural consolidation.

## Development

```console
$ GOTOOLCHAIN=local go test ./...   # all tests run against local fakes, no real network
$ GOTOOLCHAIN=local go vet ./...
$ gofmt -l .
```

Structure:

```
natprobe/
├── cmd/natprobe/        # main()
└── internal/
    ├── cli/             # cobra commands, exit codes, output rendering
    └── probe/           # protocol implementations, verdicts, traces, fakes-backed tests
```
