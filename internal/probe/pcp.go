package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// PCP protocol constants (RFC 6887).
const (
	pcpVersion    = 2
	pcpOpAnnounce = 0
	pcpOpMap      = 1
	pcpHeaderLen  = 24
	pcpMapLen     = 36
)

// IANA protocol numbers for the MAP opcode.
const (
	protoTCP = 6
	protoUDP = 17
)

// pcpResultText names RFC 6887 §7.4 result codes.
func pcpResultText(rc byte) string {
	switch rc {
	case 0:
		return "success"
	case 1:
		return "unsupported version"
	case 2:
		return "not authorized / PCP disabled on the gateway"
	case 3:
		return "malformed request"
	case 4:
		return "unsupported opcode"
	case 5:
		return "unsupported option"
	case 6:
		return "malformed option"
	case 7:
		return "network failure"
	case 8:
		return "no resources"
	case 9:
		return "unsupported protocol"
	case 10:
		return "user exceeded quota"
	case 11:
		return "cannot provide external port (gateway would remap)"
	case 12:
		return "address mismatch (request crossed a NAT)"
	case 13:
		return "excessive remote peers"
	default:
		return "unknown result code"
	}
}

// PCPAnnounce sends an ANNOUNCE request (RFC 6887 §14.1): the canonical
// "does this gateway speak PCP?" probe. Returns the server epoch and RTT.
func PCPAnnounce(ctx context.Context, gw, self netip.Addr, timeout time.Duration, trace *Trace) (epoch uint32, rtt time.Duration, err error) {
	req := make([]byte, pcpHeaderLen)
	req[0] = pcpVersion
	req[1] = pcpOpAnnounce
	if self.IsValid() {
		selfBytes := self.As16()
		copy(req[8:24], selfBytes[:])
	}
	trace.Send("PCP ANNOUNCE request -> "+fmtAddrPort(gw, natpmpPort), req, []string{
		fmt.Sprintf("version=%d opcode=0x%02x (ANNOUNCE) client=%s", pcpVersion, pcpOpAnnounce, self),
	})
	start := time.Now()
	resp, err := udpRoundTrip(ctx, gw, natpmpPort, req, timeout)
	rtt = time.Since(start)
	if err != nil {
		trace.Notef("no PCP answer: %v", err)
		return 0, rtt, err
	}
	if len(resp) < pcpHeaderLen {
		trace.Recv("PCP response (short)", resp, nil)
		return 0, rtt, fmt.Errorf("%w: short PCP response (%d bytes)", ErrUnsupported, len(resp))
	}
	rc := resp[3]
	epoch = binary.BigEndian.Uint32(resp[8:12])
	trace.Recv("PCP ANNOUNCE response", resp[:pcpHeaderLen], []string{
		fmt.Sprintf("version=%d opcode=0x%02x result=%d (%s) epoch=%d", resp[0], resp[1], rc, pcpResultText(rc), epoch),
	})
	if resp[0] == 0 {
		// A NAT-PMP-only gateway answers PCP with a NAT-PMP version-0
		// "unsupported version" error.
		return 0, rtt, fmt.Errorf("%w: gateway answered with NAT-PMP version 0 (PCP not spoken)", ErrUnsupported)
	}
	if rc != 0 {
		return epoch, rtt, fmt.Errorf("%w: PCP ANNOUNCE result %d (%s)", ErrUnsupported, rc, pcpResultText(rc))
	}
	return epoch, rtt, nil
}

// PCPMap requests a mapping via the MAP opcode (RFC 6887 §11). lifetime 0 is
// a delete/probe. A remapped grant is returned in the Lease with
// ErrPortRemapped joined, not rolled back.
func PCPMap(ctx context.Context, gw, self netip.Addr, spec Spec, lifetime, timeout time.Duration, trace *Trace) (Lease, error) {
	if !self.IsValid() {
		return Lease{}, fmt.Errorf("%w: PCP needs the client's own address", ErrUnsupported)
	}

	// Request: 24-byte header + 36-byte MAP opcode payload.
	req := make([]byte, pcpHeaderLen+pcpMapLen)
	req[0] = pcpVersion
	req[1] = pcpOpMap // R bit 0 = request
	binary.BigEndian.PutUint32(req[4:8], uint32(lifetime.Seconds()))
	selfBytes := self.As16()
	copy(req[8:24], selfBytes[:])

	nonce := req[24:36]
	if _, err := rand.Read(nonce); err != nil {
		return Lease{}, err
	}
	if spec.Proto == TCP {
		req[36] = protoTCP
	} else {
		req[36] = protoUDP
	}
	binary.BigEndian.PutUint16(req[40:42], spec.Internal)
	binary.BigEndian.PutUint16(req[42:44], spec.External)
	// Suggested external address: all-zeros v4-mapped (let the gateway pick
	// its own external address, but keep our requested port).
	suggested := netip.IPv4Unspecified().As16()
	copy(req[44:60], suggested[:])

	trace.Send("PCP MAP request -> "+fmtAddrPort(gw, natpmpPort), req, []string{
		fmt.Sprintf("version=%d opcode=0x%02x (MAP) lifetime=%ds client=%s", pcpVersion, pcpOpMap, int(lifetime.Seconds()), self),
		fmt.Sprintf("nonce=%x proto=%d internal=%d suggested_external_port=%d", nonce, req[36], spec.Internal, spec.External),
	})

	resp, err := udpRoundTrip(ctx, gw, natpmpPort, req, timeout)
	if err != nil {
		trace.Notef("no PCP answer: %v", err)
		return Lease{}, err
	}
	if len(resp) < pcpHeaderLen+pcpMapLen {
		trace.Recv("PCP response (short)", resp, nil)
		return Lease{}, fmt.Errorf("%w: short PCP response (%d bytes)", ErrUnsupported, len(resp))
	}
	rc := resp[3]
	grantedLifetime := time.Duration(binary.BigEndian.Uint32(resp[4:8])) * time.Second
	grantedPort := binary.BigEndian.Uint16(resp[42:44])
	grantedAddr := netip.AddrFrom16([16]byte(resp[44:60])).Unmap()
	trace.Recv("PCP MAP response", resp[:pcpHeaderLen+pcpMapLen], []string{
		fmt.Sprintf("version=%d opcode=0x%02x result=%d (%s) epoch=%d", resp[0], resp[1], rc, pcpResultText(rc), binary.BigEndian.Uint32(resp[8:12])),
		fmt.Sprintf("granted lifetime=%s external=%s:%d", grantedLifetime, grantedAddr, grantedPort),
	})
	if rc != 0 {
		return Lease{}, fmt.Errorf("%w: PCP MAP result %d (%s)", ErrUnsupported, rc, pcpResultText(rc))
	}
	if !bytes.Equal(resp[24:36], nonce) {
		return Lease{}, fmt.Errorf("%w: PCP nonce mismatch (response was not for our request)", ErrUnsupported)
	}

	lease := Lease{
		Spec:      spec,
		External:  netip.AddrPortFrom(grantedAddr, grantedPort),
		Lifetime:  grantedLifetime,
		GrantedAt: time.Now(),
		Protocol:  "pcp",
	}
	if lifetime > 0 && grantedPort != spec.External {
		return lease, fmt.Errorf("%w: wanted %d, got %d", ErrPortRemapped, spec.External, grantedPort)
	}
	return lease, nil
}

// PCPUnmap deletes a mapping: a MAP request with lifetime 0 (RFC 6887 §15).
func PCPUnmap(ctx context.Context, gw, self netip.Addr, spec Spec, timeout time.Duration, trace *Trace) error {
	_, err := PCPMap(ctx, gw, self, spec, 0, timeout, trace)
	return err
}
