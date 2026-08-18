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

const testTimeout = 2 * time.Second

// fakeNATPMPGateway answers NAT-PMP on an ephemeral localhost UDP port.
// grantPort lets it simulate a remap; external is the advertised IPv4;
// resultCode lets it simulate refusals.
type fakeNATPMPGateway struct {
	grantPort  func(requested uint16) uint16
	external   [4]byte
	resultCode uint16
	deletes    chan Spec
}

func startFakeNATPMPGateway(t *testing.T, fake *fakeNATPMPGateway) netip.Addr {
	t.Helper()
	if fake.grantPort == nil {
		fake.grantPort = func(requested uint16) uint16 { return requested }
	}
	if fake.deletes == nil {
		fake.deletes = make(chan Spec, 16)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 || buf[0] != 0 {
				continue
			}
			op := buf[1]
			switch op {
			case natpmpOpExternal:
				resp := make([]byte, 12)
				resp[1] = 128 + natpmpOpExternal
				binary.BigEndian.PutUint16(resp[2:4], fake.resultCode)
				binary.BigEndian.PutUint32(resp[4:8], 12345)
				copy(resp[8:12], fake.external[:])
				if _, err := conn.WriteToUDP(resp, remote); err != nil {
					return
				}
			case natpmpOpMapUDP, natpmpOpMapTCP:
				internal := binary.BigEndian.Uint16(buf[4:6])
				requested := binary.BigEndian.Uint16(buf[6:8])
				lifetime := binary.BigEndian.Uint32(buf[8:12])
				if requested == 0 && lifetime == 0 {
					proto := UDP
					if op == natpmpOpMapTCP {
						proto = TCP
					}
					fake.deletes <- Spec{Internal: internal, Proto: proto}
				}
				resp := make([]byte, 16)
				resp[1] = 128 + op
				binary.BigEndian.PutUint16(resp[2:4], fake.resultCode)
				binary.BigEndian.PutUint16(resp[8:10], internal)
				binary.BigEndian.PutUint16(resp[10:12], fake.grantPort(requested))
				binary.BigEndian.PutUint32(resp[12:16], lifetime)
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

// swapNATPMPPort points the protocol at a fake gateway port for one test.
func swapNATPMPPort(t *testing.T, port uint16) {
	t.Helper()
	orig := natpmpPort
	natpmpPort = port
	t.Cleanup(func() { natpmpPort = orig })
}

func TestNATPMPExternalAddress(t *testing.T) {
	gw := startFakeNATPMPGateway(t, &fakeNATPMPGateway{external: [4]byte{203, 0, 113, 7}})

	trace := &Trace{}
	addr, epoch, rtt, err := NATPMPExternal(context.Background(), gw, testTimeout, trace)
	if err != nil {
		t.Fatal(err)
	}
	if addr != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("external = %s", addr)
	}
	if epoch != 12345 {
		t.Errorf("epoch = %d", epoch)
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want positive", rtt)
	}
	if len(trace.Entries()) < 2 {
		t.Errorf("trace should record send+recv, got %d entries", len(trace.Entries()))
	}
}

func TestNATPMPMapGrantsLease(t *testing.T) {
	gw := startFakeNATPMPGateway(t, &fakeNATPMPGateway{external: [4]byte{203, 0, 113, 7}})

	lease, err := NATPMPMap(context.Background(), gw, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if lease.External.Port() != 8080 || lease.External.Addr() != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("bad lease: %+v", lease)
	}
	if lease.Lifetime != 120*time.Second {
		t.Errorf("lifetime: %v", lease.Lifetime)
	}
	if lease.Remapped() {
		t.Error("lease should not be a remap")
	}
}

func TestNATPMPMapRemapIsReportedNotRolledBack(t *testing.T) {
	fake := &fakeNATPMPGateway{
		external:  [4]byte{203, 0, 113, 7},
		grantPort: func(uint16) uint16 { return 61000 },
	}
	gw := startFakeNATPMPGateway(t, fake)

	lease, err := NATPMPMap(context.Background(), gw, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if !errors.Is(err, ErrPortRemapped) {
		t.Fatalf("want ErrPortRemapped, got %v", err)
	}
	// Diagnostic behavior: the surprise lease is REPORTED, not deleted.
	if lease.External.Port() != 61000 {
		t.Errorf("remapped lease must carry the granted port, got %+v", lease)
	}
	if !lease.Remapped() {
		t.Error("Remapped() must be true")
	}
	select {
	case s := <-fake.deletes:
		t.Errorf("natprobe must not auto-delete a remapped grant (deleted %v)", s)
	default:
	}
}

func TestNATPMPRefusalIsUnsupported(t *testing.T) {
	gw := startFakeNATPMPGateway(t, &fakeNATPMPGateway{resultCode: 2})

	_, _, _, err := NATPMPExternal(context.Background(), gw, testTimeout, &Trace{})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("want ErrUnsupported for result code 2, got %v", err)
	}
	if Classify(err) != VerdictUnsupported {
		t.Errorf("verdict = %s", Classify(err))
	}
}

func TestNATPMPTimeout(t *testing.T) {
	// A localhost port nothing listens on: refused/timeout = ErrTimeout.
	swapNATPMPPort(t, 1)
	_, _, _, err := NATPMPExternal(context.Background(), netip.MustParseAddr("127.0.0.1"), 500*time.Millisecond, &Trace{})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("want ErrTimeout, got %v", err)
	}
	if Classify(err) != VerdictTimeout {
		t.Errorf("verdict = %s", Classify(err))
	}
}

func TestNATPMPUnmapSendsDelete(t *testing.T) {
	fake := &fakeNATPMPGateway{external: [4]byte{203, 0, 113, 7}}
	gw := startFakeNATPMPGateway(t, fake)

	if err := NATPMPUnmap(context.Background(), gw, Spec{Internal: 8080, External: 8080, Proto: TCP}, testTimeout, &Trace{}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-fake.deletes:
		if s.Internal != 8080 || s.Proto != TCP {
			t.Errorf("deleted %+v", s)
		}
	case <-time.After(time.Second):
		t.Error("gateway never saw the delete request")
	}
}
