package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakePCPGateway answers PCP v2 on an ephemeral localhost UDP port.
type fakePCPGateway struct {
	external   netip.Addr
	grantPort  func(requested uint16) uint16
	resultCode byte
	// natpmpOnly makes it answer like a NAT-PMP-only router: version 0,
	// result 1 (unsupported version).
	natpmpOnly bool
}

func startFakePCPGateway(t *testing.T, fake *fakePCPGateway) netip.Addr {
	t.Helper()
	if fake.grantPort == nil {
		fake.grantPort = func(requested uint16) uint16 { return requested }
	}
	if !fake.external.IsValid() {
		fake.external = netip.MustParseAddr("203.0.113.7")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1200)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if fake.natpmpOnly {
				resp := make([]byte, 8)
				resp[0] = 0
				resp[1] = 128
				binary.BigEndian.PutUint16(resp[2:4], 1) // unsupported version
				if _, err := conn.WriteToUDP(resp, remote); err != nil {
					return
				}
				continue
			}
			if n < pcpHeaderLen || buf[0] != pcpVersion {
				continue
			}
			op := buf[1]
			switch op {
			case pcpOpAnnounce:
				resp := make([]byte, pcpHeaderLen)
				resp[0] = pcpVersion
				resp[1] = 0x80 | pcpOpAnnounce
				resp[3] = fake.resultCode
				binary.BigEndian.PutUint32(resp[8:12], 777)
				if _, err := conn.WriteToUDP(resp, remote); err != nil {
					return
				}
			case pcpOpMap:
				if n < pcpHeaderLen+pcpMapLen {
					continue
				}
				lifetime := binary.BigEndian.Uint32(buf[4:8])
				requested := binary.BigEndian.Uint16(buf[42:44])
				resp := make([]byte, pcpHeaderLen+pcpMapLen)
				resp[0] = pcpVersion
				resp[1] = 0x80 | pcpOpMap
				resp[3] = fake.resultCode
				binary.BigEndian.PutUint32(resp[4:8], lifetime)
				binary.BigEndian.PutUint32(resp[8:12], 777)
				copy(resp[24:36], buf[24:36]) // echo the nonce
				resp[36] = buf[36]
				binary.BigEndian.PutUint16(resp[40:42], binary.BigEndian.Uint16(buf[40:42]))
				binary.BigEndian.PutUint16(resp[42:44], fake.grantPort(requested))
				ext := fake.external.As16()
				copy(resp[44:60], ext[:])
				if _, err := conn.WriteToUDP(resp, remote); err != nil {
					return
				}
			}
		}
	}()

	local := conn.LocalAddr().(*net.UDPAddr)
	swapNATPMPPort(t, uint16(local.Port))
	return netip.MustParseAddr("127.0.0.1")
}

var testSelf = netip.MustParseAddr("192.168.1.50")

func TestPCPAnnounce(t *testing.T) {
	gw := startFakePCPGateway(t, &fakePCPGateway{})

	epoch, rtt, err := PCPAnnounce(context.Background(), gw, testSelf, testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 777 {
		t.Errorf("epoch = %d", epoch)
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v", rtt)
	}
}

func TestPCPAnnounceAgainstNATPMPOnlyGateway(t *testing.T) {
	gw := startFakePCPGateway(t, &fakePCPGateway{natpmpOnly: true})

	_, _, err := PCPAnnounce(context.Background(), gw, testSelf, testTimeout, &Trace{})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("a NAT-PMP version-0 answer must classify as unsupported, got %v", err)
	}
}

func TestPCPMapGrantsLease(t *testing.T) {
	gw := startFakePCPGateway(t, &fakePCPGateway{})

	lease, err := PCPMap(context.Background(), gw, testSelf, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if lease.External.String() != "203.0.113.7:8080" {
		t.Errorf("external = %s", lease.External)
	}
	if lease.Lifetime != 120*time.Second {
		t.Errorf("lifetime = %v", lease.Lifetime)
	}
	if lease.Protocol != "pcp" {
		t.Errorf("protocol = %s", lease.Protocol)
	}
}

func TestPCPMapRemapIsReported(t *testing.T) {
	gw := startFakePCPGateway(t, &fakePCPGateway{grantPort: func(uint16) uint16 { return 61000 }})

	lease, err := PCPMap(context.Background(), gw, testSelf, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if !errors.Is(err, ErrPortRemapped) {
		t.Fatalf("want ErrPortRemapped, got %v", err)
	}
	if lease.External.Port() != 61000 || !lease.Remapped() {
		t.Errorf("remapped lease must carry the granted port: %+v", lease)
	}
}

func TestPCPMapRefusal(t *testing.T) {
	gw := startFakePCPGateway(t, &fakePCPGateway{resultCode: 2})

	_, err := PCPMap(context.Background(), gw, testSelf, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("want ErrUnsupported for result 2, got %v", err)
	}
}

func TestPCPZeroLifetimeProbeSkipsRemapCheck(t *testing.T) {
	// A 0-lifetime MAP is the delete/probe form; a "remapped" port there is
	// normal and must not be flagged.
	gw := startFakePCPGateway(t, &fakePCPGateway{grantPort: func(uint16) uint16 { return 0 }})

	lease, err := PCPMap(context.Background(), gw, testSelf, Spec{Internal: 9, External: 9, Proto: UDP}, 0, testTimeout, &Trace{})
	if err != nil {
		t.Fatalf("0-lifetime probe must not fail on port mismatch: %v", err)
	}
	if lease.External.Addr() != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("external addr = %s", lease.External.Addr())
	}
}
