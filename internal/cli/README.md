# internal/cli

Cobra command wiring for natprobe. All protocol logic lives in
`internal/probe`; this package only parses flags, renders output, and maps
outcomes to exit codes (0 = success / any protocol works, 1 = probe failure,
2 = configuration error).

```
cli/
├── root.go      # Root command, shared flags (-v, --gateway, --timeout),
│                # signal handling (cleanup on Ctrl-C), exit-code plumbing,
│                # transcript rendering
├── gateway.go   # natprobe gateway — discovery + 5351/1900 udp liveness
├── check.go     # natprobe check — verdict table, CGNAT/double-NAT/echo analysis
├── mapcmd.go    # natprobe map / unmap — real mappings with deferred cleanup,
│                # remap reporting, --verify, privileged-port guard
├── upnpcmd.go   # natprobe upnp describe — device description + mapping table
└── cli_test.go  # Flag/spec/exit-code unit tests
```
