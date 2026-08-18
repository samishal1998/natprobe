package probe

import (
	"strings"
	"testing"
)

func TestParseSpec(t *testing.T) {
	cases := []struct {
		raw  string
		want Spec
	}{
		{"8080/tcp", Spec{Internal: 8080, External: 8080, Proto: TCP}},
		{"8443:8081/tcp", Spec{Internal: 8081, External: 8443, Proto: TCP}},
		{"5353/udp", Spec{Internal: 5353, External: 5353, Proto: UDP}},
		{" 8080/TCP ", Spec{Internal: 8080, External: 8080, Proto: TCP}},
	}
	for _, c := range cases {
		got, err := ParseSpec(c.raw)
		if err != nil {
			t.Errorf("ParseSpec(%q): %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSpec(%q) = %+v, want %+v", c.raw, got, c.want)
		}
	}
}

func TestParseSpecRejectsInvalid(t *testing.T) {
	for _, raw := range []string{
		"",           // empty
		"8080",       // no protocol
		"8080/sctp",  // unknown protocol
		"0/tcp",      // port 0
		"65536/tcp",  // out of range
		"x:8080/tcp", // non-numeric external
		"8080:y/udp", // non-numeric internal
	} {
		if _, err := ParseSpec(raw); err == nil {
			t.Errorf("ParseSpec(%q) should fail", raw)
		}
	}
}

func TestSpecString(t *testing.T) {
	if s := (Spec{Internal: 8080, External: 8080, Proto: TCP}).String(); s != "8080/tcp" {
		t.Errorf("String() = %q", s)
	}
	if s := (Spec{Internal: 8081, External: 8443, Proto: TCP}).String(); s != "8443:8081/tcp" {
		t.Errorf("String() = %q", s)
	}
}

func TestSpecPrivileged(t *testing.T) {
	if !(Spec{Internal: 443, External: 8443, Proto: TCP}).Privileged() {
		t.Error("internal 443 is privileged")
	}
	if !(Spec{Internal: 8443, External: 80, Proto: TCP}).Privileged() {
		t.Error("external 80 is privileged")
	}
	if (Spec{Internal: 8080, External: 8080, Proto: TCP}).Privileged() {
		t.Error("8080 is not privileged")
	}
}

func TestHexDump(t *testing.T) {
	got := HexDump([]byte{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xcb, 0x00, 0x71, 0x02})
	want := "0000  00 80 00 00 00 00 30 39  cb 00 71 02              ......09..q."
	if got != want {
		t.Errorf("HexDump:\n got %q\nwant %q", got, want)
	}
}

func TestHexDumpMultiRowAndAscii(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: x\r\n")
	got := HexDump(data)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 rows for %d bytes, got %d:\n%s", len(data), len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "0000  ") || !strings.HasPrefix(lines[1], "0010  ") {
		t.Errorf("offsets wrong:\n%s", got)
	}
	if !strings.Contains(lines[0], "GET / HTTP/1.1..") {
		t.Errorf("ASCII gutter should render printable bytes and dot the CRLF:\n%s", got)
	}
}

func TestHexDumpEmpty(t *testing.T) {
	if got := HexDump(nil); got != "(empty)" {
		t.Errorf("HexDump(nil) = %q", got)
	}
}

func TestTraceRendersAnnotations(t *testing.T) {
	trace := &Trace{}
	trace.Send("NAT-PMP request", []byte{0, 0}, []string{"version=0 opcode=0x00"})
	out := trace.String()
	if !strings.Contains(out, ">> NAT-PMP request") || !strings.Contains(out, "version=0 opcode=0x00") {
		t.Errorf("trace output:\n%s", out)
	}
}
