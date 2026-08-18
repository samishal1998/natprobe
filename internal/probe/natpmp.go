package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

// natpmpPort is the gateway UDP port for both NAT-PMP and PCP (RFC 6886 §3,
// RFC 6887 §19.2). A var so tests can point at a fake gateway.
var natpmpPort uint16 = 5351

// natpmpOp codes (RFC 6886 §3.2, §3.3).
const (
	natpmpOpExternal = 0
	natpmpOpMapUDP   = 1
	natpmpOpMapTCP   = 2
)

// natpmpResultText names RFC 6886 §3.5 result codes.
func natpmpResultText(rc uint16) string {
	switch rc {
	case 0:
		return "success"
	case 1:
		return "unsupported version"
	case 2:
		return "not authorized / port mapping disabled on the gateway"
	case 3:
		return "network failure (gateway has no external address)"
	case 4:
		return "out of resources"
	case 5:
		return "unsupported opcode"
	default:
		return "unknown result code"
	}
}

// NATPMPExternal asks the gateway for its external IPv4 (RFC 6886 §3.2), the
// cheapest "is NAT-PMP alive?" probe. Returns the address, the gateway epoch
// (seconds since its mapping table was last reset), and RTT.
func NATPMPExternal(ctx context.Context, gw netip.Addr, timeout time.Duration, trace *Trace) (netip.Addr, uint32, time.Duration, error) {
	req := []byte{0, natpmpOpExternal}
	trace.Send("NAT-PMP external-address request -> "+fmtAddrPort(gw, natpmpPort), req, []string{
		"version=0 opcode=0x00 (external address request)",
	})
	start := time.Now()
	resp, err := udpRoundTrip(ctx, gw, natpmpPort, req, timeout)
	rtt := time.Since(start)
	if err != nil {
		trace.Notef("no NAT-PMP answer: %v", err)
		return netip.Addr{}, 0, rtt, err
	}
	if len(resp) < 12 {
		trace.Recv("NAT-PMP response (short)", resp, nil)
		return netip.Addr{}, 0, rtt, fmt.Errorf("%w: short NAT-PMP response (%d bytes)", ErrUnsupported, len(resp))
	}
	rc := binary.BigEndian.Uint16(resp[2:4])
	epoch := binary.BigEndian.Uint32(resp[4:8])
	addr := netip.AddrFrom4([4]byte(resp[8:12]))
	trace.Recv("NAT-PMP external-address response", resp[:12], []string{
		fmt.Sprintf("version=%d opcode=0x%02x result=%d (%s)", resp[0], resp[1], rc, natpmpResultText(rc)),
		fmt.Sprintf("epoch=%d external=%s", epoch, addr),
	})
	if rc != 0 {
		return netip.Addr{}, epoch, rtt, fmt.Errorf("%w: NAT-PMP external-address result %d (%s)", ErrUnsupported, rc, natpmpResultText(rc))
	}
	return addr, epoch, rtt, nil
}

// NATPMPMap requests a mapping (RFC 6886 §3.3). Unlike the production
// client, a remapped external port is reported in the Lease (with
// ErrPortRemapped joined for callers that care), not rolled back.
func NATPMPMap(ctx context.Context, gw netip.Addr, spec Spec, lifetime, timeout time.Duration, trace *Trace) (Lease, error) {
	op := byte(natpmpOpMapUDP)
	if spec.Proto == TCP {
		op = natpmpOpMapTCP
	}
	req := make([]byte, 12)
	req[1] = op
	binary.BigEndian.PutUint16(req[4:6], spec.Internal)
	binary.BigEndian.PutUint16(req[6:8], spec.External)
	binary.BigEndian.PutUint32(req[8:12], uint32(lifetime.Seconds()))
	trace.Send(fmt.Sprintf("NAT-PMP map request -> %s", fmtAddrPort(gw, natpmpPort)), req, []string{
		fmt.Sprintf("version=0 opcode=0x%02x (map %s)", op, spec.Proto),
		fmt.Sprintf("internal=%d requested_external=%d lifetime=%ds", spec.Internal, spec.External, int(lifetime.Seconds())),
	})

	resp, err := udpRoundTrip(ctx, gw, natpmpPort, req, timeout)
	if err != nil {
		trace.Notef("no NAT-PMP answer: %v", err)
		return Lease{}, err
	}
	if len(resp) < 16 {
		trace.Recv("NAT-PMP response (short)", resp, nil)
		return Lease{}, fmt.Errorf("%w: short NAT-PMP response (%d bytes)", ErrUnsupported, len(resp))
	}
	rc := binary.BigEndian.Uint16(resp[2:4])
	granted := binary.BigEndian.Uint16(resp[10:12])
	grantedLifetime := time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second
	trace.Recv("NAT-PMP map response", resp[:16], []string{
		fmt.Sprintf("version=%d opcode=0x%02x result=%d (%s)", resp[0], resp[1], rc, natpmpResultText(rc)),
		fmt.Sprintf("epoch=%d internal=%d granted_external=%d lifetime=%s", binary.BigEndian.Uint32(resp[4:8]), binary.BigEndian.Uint16(resp[8:10]), granted, grantedLifetime),
	})
	if rc != 0 {
		return Lease{}, fmt.Errorf("%w: NAT-PMP mapping result %d (%s)", ErrUnsupported, rc, natpmpResultText(rc))
	}

	lease := Lease{
		Spec:      spec,
		Lifetime:  grantedLifetime,
		GrantedAt: time.Now(),
		Protocol:  "nat-pmp",
	}
	external, _, _, extErr := NATPMPExternal(ctx, gw, timeout, trace)
	if extErr == nil {
		lease.External = netip.AddrPortFrom(external, granted)
	} else {
		lease.External = netip.AddrPortFrom(netip.Addr{}, granted)
	}
	if granted != spec.External {
		return lease, fmt.Errorf("%w: wanted %d, got %d", ErrPortRemapped, spec.External, granted)
	}
	return lease, nil
}

// NATPMPUnmap deletes a mapping: a map request with external port and
// lifetime both zero (RFC 6886 §3.4).
func NATPMPUnmap(ctx context.Context, gw netip.Addr, spec Spec, timeout time.Duration, trace *Trace) error {
	op := byte(natpmpOpMapUDP)
	if spec.Proto == TCP {
		op = natpmpOpMapTCP
	}
	req := make([]byte, 12)
	req[1] = op
	binary.BigEndian.PutUint16(req[4:6], spec.Internal)
	// External port and lifetime both zero = delete.
	trace.Send(fmt.Sprintf("NAT-PMP delete request -> %s", fmtAddrPort(gw, natpmpPort)), req, []string{
		fmt.Sprintf("version=0 opcode=0x%02x (map %s) internal=%d external=0 lifetime=0 (delete)", op, spec.Proto, spec.Internal),
	})
	resp, err := udpRoundTrip(ctx, gw, natpmpPort, req, timeout)
	if err != nil {
		trace.Notef("no NAT-PMP answer: %v", err)
		return err
	}
	trace.Recv("NAT-PMP delete response", resp, nil)
	return nil
}

// udpRoundTrip sends one datagram and reads one response. No retransmit
// loop: natprobe reports "no answer within the timeout" as its own finding.
func udpRoundTrip(ctx context.Context, gw netip.Addr, port uint16, req []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", fmtAddrPort(gw, port))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	buf := make([]byte, 1100)
	n, err := conn.Read(buf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, fmt.Errorf("%w: no response within %s", ErrTimeout, timeout)
		}
		// ICMP port-unreachable surfaces as "connection refused" on read:
		// the gateway is alive but nothing listens on this port.
		return nil, fmt.Errorf("%w: %v (nothing listening on %d/udp)", ErrTimeout, err, port)
	}
	return buf[:n], nil
}

func fmtAddrPort(addr netip.Addr, port uint16) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
