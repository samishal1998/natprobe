// Package cli wires the natprobe commands: gateway, check, map, unmap, and
// upnp describe. Exit codes: 0 = success (for check: at least one protocol
// works), 1 = probe-level failure (no protocol works / mapping failed),
// 2 = configuration error (bad flags, no gateway found).
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/samishal1998/natprobe/internal/probe"
)

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitConfig = 2
)

// rootFlags are the cross-cutting flags shared by all commands.
type rootFlags struct {
	verbose   bool
	gatewayIP string
	timeout   time.Duration
}

// Version is the released version, stamped at build time with
//
//	-ldflags "-X github.com/samishal1998/natprobe/internal/cli.Version=v1.2.3"
//
// It stays "dev" for a `go build` or `go install` from source, which is the
// honest answer: an unstamped binary is not a release, and saying so keeps a
// bug report from being filed against a version that was never cut.
var Version = "dev"

// Run executes the CLI and returns the process exit code.
func Run() int {
	flags := &rootFlags{}

	root := &cobra.Command{
		Use:           "natprobe",
		Short:         "Diagnose NAT traversal support (UPnP IGD, PCP, NAT-PMP) on the local gateway",
		Long:          "natprobe is `dig` for NAT traversal: it probes the LAN gateway for UPnP IGD, PCP, and NAT-PMP support, shows wire-level detail, and explains failures in plain language.",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVarP(&flags.verbose, "verbose", "v", false, "print wire-level transcripts (hex dumps with field decoding, HTTP/SOAP exchanges)")
	root.PersistentFlags().StringVar(&flags.gatewayIP, "gateway", "", "gateway IP override (default: discovered from the route table)")
	root.PersistentFlags().DurationVar(&flags.timeout, "timeout", 3*time.Second, "per-attempt timeout")

	root.AddCommand(newGatewayCmd(flags))
	root.AddCommand(newCheckCmd(flags))
	root.AddCommand(newMapCmd(flags))
	root.AddCommand(newUnmapCmd(flags))
	root.AddCommand(newUpnpCmd(flags))

	// SIGINT/SIGTERM cancel the context so deferred mapping cleanup runs.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		var coded exitError
		if ok := asExitError(err, &coded); ok {
			if coded.message != "" {
				fmt.Fprintln(os.Stderr, "natprobe:", coded.message)
			}
			return coded.code
		}
		fmt.Fprintln(os.Stderr, "natprobe:", err)
		return exitConfig
	}
	return exitOK
}

// exitError carries a specific exit code out of a command.
type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string { return e.message }

func asExitError(err error, target *exitError) bool {
	if e, ok := err.(exitError); ok {
		*target = e
		return true
	}
	return false
}

// resolveGateway applies the --gateway override or discovers from the route
// table. Failure is a config error (exit 2).
func resolveGateway(flags *rootFlags) (probe.Gateway, error) {
	if flags.gatewayIP != "" {
		gw, err := probe.GatewayFromOverride(flags.gatewayIP)
		if err != nil {
			return probe.Gateway{}, exitError{code: exitConfig, message: err.Error()}
		}
		return gw, nil
	}
	gw, err := probe.DiscoverGateway()
	if err != nil {
		return probe.Gateway{}, exitError{code: exitConfig, message: err.Error() + " — is this machine on a network? Use --gateway <ip> to force one"}
	}
	return gw, nil
}

// printTraces renders wire transcripts for -v.
func printTraces(results []probe.Result) {
	for _, r := range results {
		if len(r.Trace) == 0 {
			continue
		}
		fmt.Printf("\n--- %s transcript ---\n", r.Protocol)
		printTrace(r.Trace)
	}
}

func printTrace(entries []probe.TraceEntry) {
	for _, e := range entries {
		arrow := map[string]string{"send": ">>", "recv": "<<", "note": "--"}[e.Dir]
		fmt.Printf("%s %s %s\n", e.At.UTC().Format("2006-01-02T15:04:05.000Z"), arrow, e.Label)
		if e.Detail != "" {
			for _, line := range splitLines(e.Detail) {
				fmt.Printf("    %s\n", line)
			}
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
