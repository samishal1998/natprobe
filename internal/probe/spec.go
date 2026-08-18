// Package probe implements diagnostic probing of the three consumer NAT
// traversal protocols: NAT-PMP (RFC 6886), PCP (RFC 6887), and UPnP IGD.
//
// Unlike a production port-mapping client (see
// projects/namefi-dyndns/internal/portmap, which this package's wire-format
// code is adapted from), probe tries every protocol, records wire-level
// transcripts, and classifies failures instead of falling through a chain.
package probe

import (
	"fmt"
	"strconv"
	"strings"
)

// Proto is a transport protocol for a mapping.
type Proto string

const (
	// TCP mappings serve web/ssh style services.
	TCP Proto = "tcp"
	// UDP mappings serve game/VPN style services.
	UDP Proto = "udp"
)

// Spec is one requested port mapping.
type Spec struct {
	// Internal is the port a service listens on, on this machine.
	Internal uint16
	// External is the router port that should forward to Internal.
	External uint16
	Proto    Proto
}

// String renders the flag form back: "443/tcp" or "8443:443/tcp".
func (s Spec) String() string {
	if s.External == s.Internal {
		return fmt.Sprintf("%d/%s", s.Internal, s.Proto)
	}
	return fmt.Sprintf("%d:%d/%s", s.External, s.Internal, s.Proto)
}

// ParseSpec parses the --port flag forms:
//
//	8080/tcp         external 8080 -> internal 8080, TCP
//	8443:443/tcp     external 8443 -> internal 443, TCP
//	5353/udp         external 5353 -> internal 5353, UDP
func ParseSpec(raw string) (Spec, error) {
	ports, protoStr, ok := strings.Cut(strings.TrimSpace(strings.ToLower(raw)), "/")
	if !ok {
		return Spec{}, fmt.Errorf("invalid port spec %q: want PORT/PROTO, e.g. 8080/tcp", raw)
	}
	var proto Proto
	switch protoStr {
	case "tcp":
		proto = TCP
	case "udp":
		proto = UDP
	default:
		return Spec{}, fmt.Errorf("invalid port spec %q: protocol must be tcp or udp", raw)
	}

	extStr, intStr, hasBoth := strings.Cut(ports, ":")
	external, err := parsePort(extStr)
	if err != nil {
		return Spec{}, fmt.Errorf("invalid port spec %q: %v", raw, err)
	}
	internal := external
	if hasBoth {
		if internal, err = parsePort(intStr); err != nil {
			return Spec{}, fmt.Errorf("invalid port spec %q: %v", raw, err)
		}
	}
	return Spec{Internal: internal, External: external, Proto: proto}, nil
}

// Privileged reports whether either side of the spec is below 1024. The CLI
// refuses those without --allow-privileged: probing a well-known port risks
// clobbering a real forwarding entry someone depends on.
func (s Spec) Privileged() bool {
	return s.Internal < 1024 || s.External < 1024
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", s)
	}
	return uint16(n), nil
}
