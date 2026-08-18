package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/net/netmon"
)

// Verdict classifies one protocol's probe outcome.
type Verdict string

const (
	// VerdictSupported means the gateway answered and honored the operation.
	VerdictSupported Verdict = "supported"
	// VerdictUnsupported means the gateway answered but refused or cannot do
	// the operation (an explicit error code, an unparseable response, or no
	// WAN service).
	VerdictUnsupported Verdict = "unsupported"
	// VerdictTimeout means the gateway never answered within the timeout.
	VerdictTimeout Verdict = "timeout"
	// VerdictError means a local error prevented the probe (socket failure).
	VerdictError Verdict = "error"
)

// Sentinel errors, mirroring namefi-dyndns/internal/portmap semantics.
var (
	// ErrTimeout means the gateway did not answer at all.
	ErrTimeout = errors.New("gateway did not answer")
	// ErrUnsupported means the gateway answered but refuses this operation.
	ErrUnsupported = errors.New("gateway does not support this operation")
	// ErrPortRemapped is diagnostic-only here: the router granted a
	// DIFFERENT external port than requested. natprobe reports it rather
	// than failing (unlike the production request-or-nothing policy).
	ErrPortRemapped = errors.New("router granted a different external port than requested")
)

// Classify maps an error to a Verdict.
func Classify(err error) Verdict {
	switch {
	case err == nil:
		return VerdictSupported
	case errors.Is(err, ErrTimeout):
		return VerdictTimeout
	case errors.Is(err, ErrUnsupported), errors.Is(err, ErrPortRemapped):
		// The gateway spoke the protocol; a refusal is still "answered".
		return VerdictUnsupported
	default:
		return VerdictError
	}
}

// Result is one protocol's probe outcome, the unit of the check verdict
// table and the --json schema.
type Result struct {
	// Protocol is "nat-pmp", "pcp", or "upnp".
	Protocol string `json:"protocol"`
	// Verdict is supported/unsupported/timeout/error.
	Verdict Verdict `json:"verdict"`
	// RTT is the observed round-trip time for the decisive exchange.
	RTT time.Duration `json:"rtt_ns"`
	// External is the gateway-reported external IPv4 ("" when unknown).
	External string `json:"external,omitempty"`
	// Server describes the responder (UPnP SERVER header, friendlyName,
	// model; PCP version; NAT-PMP epoch) when available.
	Server string `json:"server,omitempty"`
	// Detail is the plain-language explanation, including the likely cause
	// on failure.
	Detail string `json:"detail,omitempty"`
	// Trace is the wire transcript (populated for -v / --json).
	Trace []TraceEntry `json:"trace,omitempty"`
}

// AnySupported reports whether at least one result is supported: the exit
// code 0/1 pivot for natprobe check.
func AnySupported(results []Result) bool {
	for _, r := range results {
		if r.Verdict == VerdictSupported {
			return true
		}
	}
	return false
}

// IsCGNATv4 reports an address inside 100.64.0.0/10 (RFC 6598,
// carrier-grade NAT). A gateway whose "external" address is CGNAT cannot
// make a v4 mapping reachable from the internet.
func IsCGNATv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

// IsPrivateV4 reports an RFC 1918 address, the "double NAT" tell when the
// gateway's external side is itself private.
func IsPrivateV4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsPrivate()
}

// Gateway describes the discovered LAN gateway.
type Gateway struct {
	// Addr is the gateway's LAN address.
	Addr netip.Addr `json:"gateway"`
	// Self is this machine's own LAN address on the gateway's network.
	Self netip.Addr `json:"self"`
	// Interface is the network interface facing the gateway, when known.
	Interface string `json:"interface,omitempty"`
}

// DiscoverGateway finds the LAN gateway and own address from the OS route
// table (same mechanism as namefi-dyndns), plus the interface holding Self.
func DiscoverGateway() (Gateway, error) {
	gw, self, ok := netmon.LikelyHomeRouterIP()
	if !ok {
		return Gateway{}, errors.New("no LAN gateway found in the route table")
	}
	g := Gateway{Addr: gw, Self: self}
	g.Interface = interfaceFor(self)
	return g, nil
}

// GatewayFromOverride builds a Gateway for --gateway <ip>: the own address
// is picked by asking the OS which source address routes toward it.
func GatewayFromOverride(ip string) (Gateway, error) {
	gw, err := netip.ParseAddr(ip)
	if err != nil {
		return Gateway{}, fmt.Errorf("--gateway %q is not an IP address", ip)
	}
	g := Gateway{Addr: gw}
	if conn, err := net.Dial("udp4", fmt.Sprintf("%s:9", gw)); err == nil {
		if local, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if self, ok := netip.AddrFromSlice(local.IP); ok {
				g.Self = self.Unmap()
			}
		}
		conn.Close()
	}
	g.Interface = interfaceFor(g.Self)
	return g, nil
}

func interfaceFor(self netip.Addr) string {
	if !self.IsValid() {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ipnet.IP); ok && addr.Unmap() == self {
				return iface.Name
			}
		}
	}
	return ""
}

// UDPProbe reports whether the gateway answers anything at all on the given
// UDP port within the timeout: a lighter "is anyone home" check than a full
// protocol exchange. For 5351 it sends a NAT-PMP external-address request
// (harmless read); for 1900 an SSDP M-SEARCH.
func UDPProbe(ctx context.Context, gw netip.Addr, port uint16, payload []byte, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", fmt.Sprintf("%s:%d", gw, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return false
		}
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, 2048)
	_, err = conn.Read(buf)
	return err == nil
}
