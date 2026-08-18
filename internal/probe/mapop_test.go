package probe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMapProtocolReportsRemap(t *testing.T) {
	startFakePCPGateway(t, &fakePCPGateway{grantPort: func(uint16) uint16 { return 61000 }})

	gw := Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Self: testSelf}
	attempt := MapProtocol(context.Background(), "pcp", gw, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout)
	if attempt.Verdict != VerdictSupported {
		t.Errorf("a remap still proves the protocol works: verdict = %s (%s)", attempt.Verdict, attempt.Detail)
	}
	if !attempt.Remapped {
		t.Error("Remapped must be set")
	}
	if attempt.Lease == nil || attempt.Lease.External.Port() != 61000 {
		t.Errorf("the granted lease must be kept for cleanup: %+v", attempt.Lease)
	}
	if attempt.Detail != "router granted a different port (61000): treat as remap" {
		t.Errorf("detail = %q", attempt.Detail)
	}
}

func TestMapProtocolTimeoutNamesLikelyCause(t *testing.T) {
	swapNATPMPPort(t, 1)
	gw := Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Self: testSelf}
	attempt := MapProtocol(context.Background(), "natpmp", gw, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, 500*time.Millisecond)
	if attempt.Verdict != VerdictTimeout {
		t.Errorf("verdict = %s", attempt.Verdict)
	}
	if attempt.Lease != nil {
		t.Error("no lease on timeout")
	}
	if attempt.Detail == "" {
		t.Error("timeout must carry a likely-cause explanation")
	}
}

func TestVerifyTCPRoundTrip(t *testing.T) {
	// Grab a free port, then point Verify's "external" at loopback: the
	// temporary listener and the connect meet on the same port, proving the
	// listener/probe plumbing end to end without a real NAT.
	probeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probeListener.Addr().(*net.TCPAddr).Port)
	probeListener.Close()

	spec := Spec{Internal: port, External: port, Proto: TCP}
	res := Verify(context.Background(), spec, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), testTimeout)
	if !res.Reached {
		t.Errorf("verify should reach its own listener via loopback: %s", res.Detail)
	}
	if !res.Hairpin {
		t.Error("the hairpin caveat must always be flagged for in-LAN checks")
	}
}

func TestVerifyUDPRoundTrip(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	pc.Close()

	spec := Spec{Internal: port, External: port, Proto: UDP}
	res := Verify(context.Background(), spec, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), testTimeout)
	if !res.Reached {
		t.Errorf("verify should echo through loopback: %s", res.Detail)
	}
}

func TestVerifyWithoutExternalAddress(t *testing.T) {
	res := Verify(context.Background(), Spec{Internal: 8080, External: 8080, Proto: TCP}, netip.AddrPort{}, time.Second)
	if res.Reached {
		t.Error("cannot verify without an address")
	}
}
