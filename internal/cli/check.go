package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/samishal1998/natprobe/internal/probe"
)

func newCheckCmd(flags *rootFlags) *cobra.Command {
	var jsonOut, echo bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Probe all three protocols and print a verdict table",
		Long:  "Probes NAT-PMP, PCP, and UPnP IGD concurrently (all of them, not first-win) and prints per-protocol verdicts, round-trip times, the gateway-reported external address, and CGNAT / double-NAT analysis.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			gw, err := resolveGateway(flags)
			if err != nil {
				return err
			}
			report := probe.Check(cmd.Context(), probe.CheckOptions{
				Gateway: gw,
				Timeout: flags.timeout,
				Echo:    echo,
			})

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
					return err
				}
			} else {
				printCheckReport(report, flags.verbose)
			}
			if !report.AnyProtocolWorks() {
				return exitError{code: exitFailed}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	cmd.Flags().BoolVar(&echo, "echo", false, "also compare against a public what-is-my-ip endpoint (sends one outbound HTTPS request)")
	return cmd
}

func printCheckReport(report probe.CheckReport, verbose bool) {
	fmt.Printf("Gateway %s (checked %s)\n\n", report.Gateway.Addr, report.CheckedAt.Format("2006-01-02T15:04:05Z"))

	// Verdict table.
	fmt.Printf("%-9s %-13s %-9s %-17s %s\n", "PROTOCOL", "VERDICT", "RTT", "EXTERNAL", "DETAIL")
	for _, r := range report.Results {
		external := r.External
		if external == "" {
			external = "-"
		}
		fmt.Printf("%-9s %-13s %-9s %-17s %s\n", r.Protocol, verdictLabel(r.Verdict), roundRTT(r.RTT), external, r.Detail)
		if r.Server != "" {
			fmt.Printf("%-9s %-13s %-9s %-17s server: %s\n", "", "", "", "", r.Server)
		}
	}
	fmt.Println()

	switch {
	case report.CGNAT:
		fmt.Printf("External address %s is carrier-grade NAT (100.64.0.0/10): your ISP shares one public address across customers. Port mappings on this router cannot make you reachable from the internet.\n", report.External)
	case report.DoubleNAT:
		fmt.Printf("External address %s is a private (RFC 1918) address: this router itself sits behind another NAT. A mapping here only forwards to the next NAT layer, not the internet.\n", report.External)
	case report.External != "":
		fmt.Printf("Gateway-reported external address: %s\n", report.External)
	default:
		fmt.Println("No protocol reported an external address.")
	}
	if report.EchoAddress != "" {
		if report.EchoMismatch {
			fmt.Printf("Outside observer sees %s, which differs from the gateway-reported %s — traffic is NATed again beyond this router.\n", report.EchoAddress, report.External)
		} else {
			fmt.Printf("Outside observer agrees: %s\n", report.EchoAddress)
		}
	}

	if !report.AnyProtocolWorks() {
		fmt.Println("\nNo NAT traversal protocol works on this gateway. Port forwarding must be configured manually in the router's admin UI, if at all.")
	}

	if verbose {
		printTraces(report.Results)
	}
}

func verdictLabel(v probe.Verdict) string {
	switch v {
	case probe.VerdictSupported:
		return "supported"
	case probe.VerdictTimeout:
		return "timeout"
	case probe.VerdictUnsupported:
		return "unsupported"
	default:
		return string(v)
	}
}

func roundRTT(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Millisecond:
		return d.Round(10 * time.Microsecond).String()
	default:
		return d.Round(time.Millisecond).String()
	}
}
