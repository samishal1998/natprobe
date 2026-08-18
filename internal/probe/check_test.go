package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want Verdict
	}{
		{nil, VerdictSupported},
		{ErrTimeout, VerdictTimeout},
		{fmt.Errorf("wrapped: %w", ErrTimeout), VerdictTimeout},
		{ErrUnsupported, VerdictUnsupported},
		{ErrPortRemapped, VerdictUnsupported},
		{fmt.Errorf("something else"), VerdictError},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}

func TestAnySupported(t *testing.T) {
	if AnySupported([]Result{{Verdict: VerdictTimeout}, {Verdict: VerdictUnsupported}}) {
		t.Error("no supported result should mean false (exit 1)")
	}
	if !AnySupported([]Result{{Verdict: VerdictTimeout}, {Verdict: VerdictSupported}}) {
		t.Error("one supported result should mean true (exit 0)")
	}
	if AnySupported(nil) {
		t.Error("empty results should mean false")
	}
}

func TestCGNATClassification(t *testing.T) {
	cases := []struct {
		addr  string
		cgnat bool
	}{
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"100.128.0.0", false}, // one past the /10
		{"100.63.255.255", false},
		{"203.0.113.7", false},
		{"192.168.1.1", false},
		{"2001:db8::1", false}, // v6 is never CGNAT-v4
	}
	for _, c := range cases {
		if got := IsCGNATv4(netip.MustParseAddr(c.addr)); got != c.cgnat {
			t.Errorf("IsCGNATv4(%s) = %v, want %v", c.addr, got, c.cgnat)
		}
	}
}

func TestDoubleNATClassification(t *testing.T) {
	if !IsPrivateV4(netip.MustParseAddr("192.168.0.1")) {
		t.Error("192.168.0.1 is private")
	}
	if IsPrivateV4(netip.MustParseAddr("203.0.113.7")) {
		t.Error("203.0.113.7 is public")
	}
}

// TestCheckAgainstAllFakes wires all three fake gateways at once and
// verifies the aggregate report. NAT-PMP and PCP share port 5351, so a
// combined fake answers both protocols on one socket via the version byte —
// here we instead run UPnP (its own port) plus the PCP fake (which answers
// version-2 PCP; NAT-PMP requests get no reply and time out).
func TestCheckAgainstPCPAndUPnPFakes(t *testing.T) {
	startFakePCPGateway(t, &fakePCPGateway{external: netip.MustParseAddr("100.64.5.6")})
	newFakeIGD(t)

	report := Check(context.Background(), CheckOptions{
		Gateway: Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Self: testSelf},
		Timeout: testTimeout,
	})

	if len(report.Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(report.Results))
	}
	byProto := map[string]Result{}
	for _, r := range report.Results {
		byProto[r.Protocol] = r
	}
	if byProto["pcp"].Verdict != VerdictSupported {
		t.Errorf("pcp verdict = %s (%s)", byProto["pcp"].Verdict, byProto["pcp"].Detail)
	}
	if byProto["upnp"].Verdict != VerdictSupported {
		t.Errorf("upnp verdict = %s (%s)", byProto["upnp"].Verdict, byProto["upnp"].Detail)
	}
	// The PCP fake ignores NAT-PMP (version 0) requests entirely.
	if byProto["nat-pmp"].Verdict != VerdictTimeout {
		t.Errorf("nat-pmp verdict = %s (%s)", byProto["nat-pmp"].Verdict, byProto["nat-pmp"].Detail)
	}
	if !report.AnyProtocolWorks() {
		t.Error("check must succeed when any protocol works")
	}
	// PCP reported 100.64.5.6 (CGNAT); result order is fixed, so nat-pmp
	// (no external) is skipped and PCP's address becomes the consensus.
	if report.External != "100.64.5.6" {
		t.Errorf("consensus external = %q", report.External)
	}
	if !report.CGNAT {
		t.Error("100.64.5.6 must be flagged as CGNAT")
	}
	if report.DoubleNAT {
		t.Error("CGNAT is not RFC 1918 double NAT")
	}
}

func TestCheckAllTimeouts(t *testing.T) {
	swapNATPMPPort(t, 1)
	swapSSDPPort(t, 1)

	report := Check(context.Background(), CheckOptions{
		Gateway: Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Self: testSelf},
		Timeout: 500 * time.Millisecond,
	})
	if report.AnyProtocolWorks() {
		t.Error("nothing should work")
	}
	for _, r := range report.Results {
		if r.Verdict != VerdictTimeout {
			t.Errorf("%s verdict = %s, want timeout", r.Protocol, r.Verdict)
		}
		if r.Detail == "" {
			t.Errorf("%s must explain the likely cause", r.Protocol)
		}
	}
}

func TestCheckEchoMismatch(t *testing.T) {
	startFakePCPGateway(t, &fakePCPGateway{external: netip.MustParseAddr("203.0.113.7")})
	swapSSDPPort(t, 1)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "198.51.100.9")
	}))
	defer echo.Close()

	report := Check(context.Background(), CheckOptions{
		Gateway: Gateway{Addr: netip.MustParseAddr("127.0.0.1"), Self: testSelf},
		Timeout: testTimeout,
		Echo:    true,
		EchoURL: echo.URL,
	})
	if report.EchoAddress != "198.51.100.9" {
		t.Errorf("echo address = %q", report.EchoAddress)
	}
	if !report.EchoMismatch {
		t.Error("echo 198.51.100.9 differs from gateway-reported 203.0.113.7 — must be flagged")
	}
}

// TestCheckReportJSONSchemaGolden pins the top-level JSON key set: the
// --json schema is documented in the README and must not drift silently.
func TestCheckReportJSONSchemaGolden(t *testing.T) {
	report := CheckReport{
		CheckedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Gateway:   Gateway{Addr: netip.MustParseAddr("192.168.1.1"), Self: netip.MustParseAddr("192.168.1.50"), Interface: "en0"},
		Results: []Result{{
			Protocol: "nat-pmp",
			Verdict:  VerdictSupported,
			RTT:      2 * time.Millisecond,
			External: "203.0.113.7",
			Server:   "epoch 12345",
			Detail:   "gateway answered the external-address request",
		}},
		External: "203.0.113.7",
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	golden := `{"checked_at":"2026-01-02T03:04:05Z","gateway":{"gateway":"192.168.1.1","self":"192.168.1.50","interface":"en0"},"results":[{"protocol":"nat-pmp","verdict":"supported","rtt_ns":2000000,"external":"203.0.113.7","server":"epoch 12345","detail":"gateway answered the external-address request"}],"external":"203.0.113.7","cgnat":false,"double_nat":false}`
	if string(data) != golden {
		t.Errorf("check --json schema drifted:\n got %s\nwant %s", data, golden)
	}
}

// TestMapAttemptJSONSchemaGolden pins the map --json attempt schema.
func TestMapAttemptJSONSchemaGolden(t *testing.T) {
	attempt := MapAttempt{
		Protocol:        "pcp",
		Verdict:         VerdictSupported,
		External:        "203.0.113.7:61000",
		LifetimeSeconds: 120,
		Remapped:        true,
		Detail:          "router granted a different port (61000): treat as remap",
	}
	data, err := json.Marshal(attempt)
	if err != nil {
		t.Fatal(err)
	}
	golden := `{"protocol":"pcp","verdict":"supported","external":"203.0.113.7:61000","lifetime_seconds":120,"remapped":true,"detail":"router granted a different port (61000): treat as remap"}`
	if string(data) != golden {
		t.Errorf("map --json schema drifted:\n got %s\nwant %s", data, golden)
	}
}
