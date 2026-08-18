package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// MapAttempt is one protocol's mapping attempt outcome, the unit of the
// natprobe map report and its --json schema.
type MapAttempt struct {
	Protocol string  `json:"protocol"`
	Verdict  Verdict `json:"verdict"`
	// External is the granted external ip:port ("" on failure; the address
	// half may be missing when only the port is known).
	External string `json:"external,omitempty"`
	// LifetimeSeconds is the gateway-granted lease duration.
	LifetimeSeconds int64 `json:"lifetime_seconds,omitempty"`
	// Remapped is true when the granted external port differs from the
	// requested one.
	Remapped bool `json:"remapped,omitempty"`
	// Detail is the plain-language explanation.
	Detail string `json:"detail,omitempty"`
	// Trace is the wire transcript.
	Trace []TraceEntry `json:"trace,omitempty"`

	// Lease carries the grant for cleanup; nil when nothing was granted.
	Lease *Lease `json:"-"`
}

// MapProtocol requests a mapping via one named protocol ("natpmp", "pcp",
// "upnp"). Unlike production, a remap is a reportable outcome, not a
// rollback: the lease is kept so the caller can still delete it.
func MapProtocol(ctx context.Context, protocol string, gw Gateway, spec Spec, lifetime, timeout time.Duration) MapAttempt {
	trace := &Trace{}
	var lease Lease
	var err error
	var name string
	switch protocol {
	case "natpmp":
		name = "nat-pmp"
		lease, err = NATPMPMap(ctx, gw.Addr, spec, lifetime, timeout, trace)
	case "pcp":
		name = "pcp"
		lease, err = PCPMap(ctx, gw.Addr, gw.Self, spec, lifetime, timeout, trace)
	case "upnp":
		name = "upnp"
		var dev *UPnPDevice
		dev, err = UPnPDiscover(ctx, gw.Addr, timeout, trace)
		if err == nil {
			lease, err = dev.AddPortMapping(ctx, gw.Self, spec, lifetime, timeout, trace)
		}
	default:
		return MapAttempt{Protocol: protocol, Verdict: VerdictError, Detail: fmt.Sprintf("unknown protocol %q", protocol)}
	}

	attempt := MapAttempt{Protocol: name, Verdict: Classify(err), Trace: trace.Entries()}
	granted := err == nil || lease.External.Port() != 0
	if granted {
		attempt.Lease = &lease
		attempt.External = renderExternal(lease.External)
		attempt.LifetimeSeconds = int64(lease.Lifetime.Seconds())
		attempt.Remapped = lease.Remapped()
	}
	switch {
	case err == nil && attempt.Remapped:
		attempt.Verdict = VerdictSupported
		attempt.Detail = fmt.Sprintf("router granted a different port (%d): treat as remap", lease.External.Port())
	case err == nil:
		attempt.Detail = "mapping granted"
	case attempt.Remapped:
		// ErrPortRemapped path: the gateway CAN map, it just moved the port.
		attempt.Verdict = VerdictSupported
		attempt.Detail = fmt.Sprintf("router granted a different port (%d): treat as remap", lease.External.Port())
	case attempt.Verdict == VerdictTimeout:
		attempt.Detail = fmt.Sprintf("gateway did not answer — %s disabled or not supported", name)
	default:
		attempt.Detail = err.Error()
	}
	return attempt
}

// UnmapProtocol deletes a mapping via one named protocol, best effort.
func UnmapProtocol(ctx context.Context, protocol string, gw Gateway, spec Spec, timeout time.Duration) error {
	trace := &Trace{}
	switch protocol {
	case "natpmp", "nat-pmp":
		return NATPMPUnmap(ctx, gw.Addr, spec, timeout, trace)
	case "pcp":
		return PCPUnmap(ctx, gw.Addr, gw.Self, spec, timeout, trace)
	case "upnp":
		dev, err := UPnPDiscover(ctx, gw.Addr, timeout, trace)
		if err != nil {
			return err
		}
		return dev.DeletePortMapping(ctx, spec, timeout, trace)
	}
	return fmt.Errorf("unknown protocol %q", protocol)
}

func renderExternal(ap netip.AddrPort) string {
	if !ap.Addr().IsValid() {
		return fmt.Sprintf("?:%d", ap.Port())
	}
	return ap.String()
}

// VerifyResult reports the end-to-end reachability check for one mapping.
type VerifyResult struct {
	// Reached is true when a connection/echo through the external address
	// succeeded.
	Reached bool `json:"reached"`
	// Hairpin notes that the check ran from inside the LAN: a failure may
	// mean the router lacks hairpin NAT, not that the mapping is broken.
	Hairpin bool   `json:"hairpin_caveat"`
	Detail  string `json:"detail"`
}

// Verify starts a temporary listener on the spec's internal port and tries
// to reach it via the granted external ip:port. TCP: connect and match a
// banner. UDP: send a token and await its echo.
func Verify(ctx context.Context, spec Spec, external netip.AddrPort, timeout time.Duration) VerifyResult {
	res := VerifyResult{Hairpin: true}
	if !external.Addr().IsValid() {
		res.Detail = "no external address known, cannot verify"
		return res
	}
	token := fmt.Sprintf("natprobe-verify-%d", time.Now().UnixNano())

	if spec.Proto == TCP {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", spec.Internal))
		if err != nil {
			res.Detail = fmt.Sprintf("could not listen on internal port %d/tcp: %v", spec.Internal, err)
			return res
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte(token))
				conn.Close()
			}
		}()

		var d net.Dialer
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := d.DialContext(dialCtx, "tcp", external.String())
		if err != nil {
			res.Detail = fmt.Sprintf("TCP connect to %s failed: %v — from inside the LAN this can mean the router lacks hairpin NAT, not that the mapping is broken; test from an outside network to be sure", external, err)
			return res
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, len(token))
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != token {
			res.Detail = fmt.Sprintf("TCP connect to %s reached SOMETHING, but not our listener — the port may be forwarded elsewhere", external)
			return res
		}
		res.Reached = true
		res.Detail = fmt.Sprintf("TCP connect to %s reached our listener (hairpin NAT works on this router)", external)
		return res
	}

	// UDP: echo the token back through the mapping.
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", spec.Internal))
	if err != nil {
		res.Detail = fmt.Sprintf("could not listen on internal port %d/udp: %v", spec.Internal, err)
		return res
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, remote, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], remote)
		}
	}()

	conn, err := net.Dial("udp", external.String())
	if err != nil {
		res.Detail = fmt.Sprintf("UDP dial to %s failed: %v", external, err)
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(token)); err != nil {
		res.Detail = fmt.Sprintf("UDP send to %s failed: %v", external, err)
		return res
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != token {
		res.Detail = fmt.Sprintf("no UDP echo back from %s — from inside the LAN this can mean the router lacks hairpin NAT, not that the mapping is broken; test from an outside network to be sure", external)
		return res
	}
	res.Reached = true
	res.Detail = fmt.Sprintf("UDP echo through %s reached our listener (hairpin NAT works on this router)", external)
	return res
}
