package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// CheckOptions configures a full protocol check.
type CheckOptions struct {
	Gateway Gateway
	Timeout time.Duration
	// Echo enables the outside-observer comparison against a public
	// what-is-my-ip endpoint (network egress; off by default).
	Echo bool
	// EchoURL overrides the echo endpoint (tests).
	EchoURL string
}

// CheckReport is the natprobe check outcome: one Result per protocol plus
// cross-protocol analysis. It is the --json schema for check.
type CheckReport struct {
	// CheckedAt is when the check ran (ISO 8601 in JSON).
	CheckedAt time.Time `json:"checked_at"`
	Gateway   Gateway   `json:"gateway"`
	// Results are per-protocol outcomes, in fixed order: nat-pmp, pcp, upnp.
	Results []Result `json:"results"`
	// External is the consensus gateway-reported external address ("" when
	// no protocol reported one).
	External string `json:"external,omitempty"`
	// CGNAT is true when the reported external address is in 100.64.0.0/10.
	CGNAT bool `json:"cgnat"`
	// DoubleNAT is true when the reported external address is RFC 1918
	// private: the gateway itself sits behind another NAT.
	DoubleNAT bool `json:"double_nat"`
	// EchoAddress is the public echo endpoint's view of our address (only
	// with --echo).
	EchoAddress string `json:"echo_address,omitempty"`
	// EchoMismatch is true when the echo address differs from the
	// gateway-reported external (only meaningful with --echo and both
	// present).
	EchoMismatch bool `json:"echo_mismatch,omitempty"`
}

// AnyProtocolWorks reports whether any protocol verdict is supported.
func (r CheckReport) AnyProtocolWorks() bool { return AnySupported(r.Results) }

// Check probes all three protocols concurrently. Every protocol is tried to
// completion — this is a diagnostic, not a first-win production client.
func Check(ctx context.Context, opts CheckOptions) CheckReport {
	report := CheckReport{CheckedAt: time.Now().UTC(), Gateway: opts.Gateway}
	gw, self := opts.Gateway.Addr, opts.Gateway.Self

	results := make([]Result, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		results[0] = checkNATPMP(ctx, gw, opts.Timeout)
	}()
	go func() {
		defer wg.Done()
		results[1] = checkPCP(ctx, gw, self, opts.Timeout)
	}()
	go func() {
		defer wg.Done()
		results[2] = checkUPnP(ctx, gw, opts.Timeout)
	}()
	wg.Wait()
	report.Results = results

	for _, r := range results {
		if r.External == "" {
			continue
		}
		report.External = r.External
		if addr, err := netip.ParseAddr(r.External); err == nil {
			if IsCGNATv4(addr) {
				report.CGNAT = true
			}
			if IsPrivateV4(addr) {
				report.DoubleNAT = true
			}
		}
		break
	}

	if opts.Echo {
		echo, err := echoAddress(ctx, opts.EchoURL, opts.Timeout)
		if err == nil {
			report.EchoAddress = echo
			if report.External != "" && echo != report.External {
				report.EchoMismatch = true
			}
		}
	}
	return report
}

func checkNATPMP(ctx context.Context, gw netip.Addr, timeout time.Duration) Result {
	trace := &Trace{}
	external, epoch, rtt, err := NATPMPExternal(ctx, gw, timeout, trace)
	r := Result{Protocol: "nat-pmp", Verdict: Classify(err), RTT: rtt, Trace: trace.Entries()}
	switch r.Verdict {
	case VerdictSupported:
		r.External = external.String()
		r.Server = fmt.Sprintf("epoch %d", epoch)
		r.Detail = "gateway answered the external-address request"
	case VerdictTimeout:
		r.Detail = fmt.Sprintf("gateway did not answer on %d/udp — NAT-PMP disabled or not supported", natpmpPort)
	default:
		r.Detail = err.Error()
	}
	return r
}

func checkPCP(ctx context.Context, gw, self netip.Addr, timeout time.Duration) Result {
	trace := &Trace{}
	epoch, rtt, err := PCPAnnounce(ctx, gw, self, timeout, trace)
	r := Result{Protocol: "pcp", Verdict: Classify(err), RTT: rtt}
	if err == nil {
		// ANNOUNCE proves PCP; a 0-lifetime MAP probe additionally reveals
		// the external address the gateway would assign.
		r.Server = fmt.Sprintf("PCP v%d, epoch %d", pcpVersion, epoch)
		r.Detail = "gateway answered ANNOUNCE"
		if self.IsValid() {
			if lease, mapErr := PCPMap(ctx, gw, self, Spec{Internal: 9, External: 9, Proto: UDP}, 0, timeout, trace); mapErr == nil && lease.External.Addr().IsValid() && !lease.External.Addr().IsUnspecified() {
				r.External = lease.External.Addr().String()
			}
		}
	} else if r.Verdict == VerdictTimeout {
		r.Detail = fmt.Sprintf("gateway did not answer on %d/udp — PCP disabled or not supported", natpmpPort)
	} else {
		r.Detail = err.Error()
	}
	r.Trace = trace.Entries()
	return r
}

func checkUPnP(ctx context.Context, gw netip.Addr, timeout time.Duration) Result {
	trace := &Trace{}
	start := time.Now()
	dev, err := UPnPDiscover(ctx, gw, timeout, trace)
	rtt := time.Since(start)
	r := Result{Protocol: "upnp", Verdict: Classify(err), RTT: rtt}
	if dev != nil {
		var parts []string
		if dev.Server != "" {
			parts = append(parts, dev.Server)
		}
		if dev.FriendlyName != "" {
			parts = append(parts, dev.FriendlyName)
		}
		if dev.ModelName != "" && dev.ModelName != dev.FriendlyName {
			parts = append(parts, dev.ModelName)
		}
		r.Server = strings.Join(parts, "; ")
	}
	if err == nil {
		if external, ipErr := dev.ExternalIP(ctx, timeout, trace); ipErr == nil {
			r.External = external.String()
			r.Detail = "IGD discovered, GetExternalIPAddress answered"
		} else {
			r.Detail = "IGD discovered, but GetExternalIPAddress failed: " + ipErr.Error()
		}
	} else if r.Verdict == VerdictTimeout {
		r.Detail = fmt.Sprintf("gateway did not answer SSDP on %d/udp — UPnP disabled or not supported", ssdpPort)
	} else {
		r.Detail = err.Error()
	}
	r.Trace = trace.Entries()
	return r
}

// defaultEchoURL is a plain-text what-is-my-ip endpoint used only with
// --echo.
const defaultEchoURL = "https://api.ipify.org"

func echoAddress(ctx context.Context, echoURL string, timeout time.Duration) (string, error) {
	if echoURL == "" {
		echoURL = defaultEchoURL
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(data)))
	if err != nil {
		return "", fmt.Errorf("echo endpoint answered %q, not an IP", strings.TrimSpace(string(data)))
	}
	return addr.String(), nil
}
