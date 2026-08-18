package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/samishal1998/natprobe/internal/probe"
)

// mapReport is the --json schema for natprobe map.
type mapReport struct {
	// MappedAt is when the run started (ISO 8601).
	MappedAt time.Time `json:"mapped_at"`
	Gateway  string    `json:"gateway"`
	// Spec echoes the request: "8080/tcp" form.
	Spec string `json:"spec"`
	// LifetimeSeconds is the requested lease duration.
	LifetimeSeconds int64 `json:"lifetime_seconds"`
	// Attempts holds one entry per protocol tried.
	Attempts []probe.MapAttempt `json:"attempts"`
	// Kept is true when --keep left the mapping(s) in place.
	Kept bool `json:"kept"`
	// Verify is the reachability check outcome (only with --verify).
	Verify *probe.VerifyResult `json:"verify,omitempty"`
}

// mapProtocols expands --protocol into the list to try.
func mapProtocols(selected string) ([]string, error) {
	switch selected {
	case "auto":
		return []string{"pcp", "natpmp", "upnp"}, nil
	case "pcp", "natpmp", "upnp":
		return []string{selected}, nil
	}
	return nil, fmt.Errorf("--protocol must be auto, pcp, natpmp, or upnp (got %q)", selected)
}

func newMapCmd(flags *rootFlags) *cobra.Command {
	var (
		jsonOut         bool
		portSpec        string
		lifetime        time.Duration
		protocol        string
		keep            bool
		verify          bool
		allowPrivileged bool
	)
	cmd := &cobra.Command{
		Use:   "map --port 8080/tcp",
		Short: "Request a real port mapping (short-lived by default, deleted on exit)",
		Long:  "Requests an actual mapping on each selected protocol, reports the granted external ip:port and lifetime, and detects remaps. The mapping is deleted before exit unless --keep is given; the default lifetime is short so leftovers expire fast anyway.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec, gw, err := parseMapArgs(flags, portSpec, allowPrivileged)
			if err != nil {
				return err
			}
			protocols, err := mapProtocols(protocol)
			if err != nil {
				return exitError{code: exitConfig, message: err.Error()}
			}

			ctx := cmd.Context()
			report := mapReport{
				MappedAt:        time.Now().UTC(),
				Gateway:         gw.Addr.String(),
				Spec:            spec.String(),
				LifetimeSeconds: int64(lifetime.Seconds()),
				Kept:            keep,
			}

			// Cleanup runs on normal exit AND SIGINT (root wires the signal
			// context; a canceled ctx still allows cleanup via a fresh
			// short-lived context).
			var granted []probe.MapAttempt
			defer func() {
				if keep {
					return
				}
				cleanupCtx, cancel := context.WithTimeout(context.Background(), flags.timeout)
				defer cancel()
				for _, a := range granted {
					cleanupSpec := spec
					if a.Lease != nil {
						cleanupSpec.External = a.Lease.External.Port()
					}
					if err := probe.UnmapProtocol(cleanupCtx, a.Protocol, gw, cleanupSpec, flags.timeout); err != nil && !jsonOut {
						fmt.Fprintf(os.Stderr, "cleanup: could not delete the %s mapping: %v\n", a.Protocol, err)
					} else if !jsonOut {
						fmt.Printf("Deleted the %s mapping.\n", a.Protocol)
					}
				}
			}()

			for _, p := range protocols {
				attempt := probe.MapProtocol(ctx, p, gw, spec, lifetime, flags.timeout)
				report.Attempts = append(report.Attempts, attempt)
				if attempt.Lease != nil {
					granted = append(granted, attempt)
				}
				if !jsonOut {
					printMapAttempt(attempt, flags.verbose)
				}
				if ctx.Err() != nil {
					break
				}
			}

			if verify && ctx.Err() == nil {
				for _, a := range granted {
					if a.Lease == nil || !a.Lease.External.Addr().IsValid() {
						continue
					}
					v := probe.Verify(ctx, spec, a.Lease.External, flags.timeout)
					report.Verify = &v
					if !jsonOut {
						fmt.Printf("Verify: %s\n", v.Detail)
					}
					break
				}
				if report.Verify == nil && !jsonOut && len(granted) > 0 {
					fmt.Println("Verify: skipped — no granted mapping carried a usable external address.")
				}
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
					return err
				}
			} else if keep && len(granted) > 0 {
				fmt.Println("Mappings kept (--keep). They expire when their lifetime runs out; delete earlier with natprobe unmap.")
			}
			if len(granted) == 0 {
				return exitError{code: exitFailed}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	cmd.Flags().StringVar(&portSpec, "port", "", "port to map, PORT/PROTO or EXT:INT/PROTO (e.g. 8080/tcp)")
	cmd.Flags().DurationVar(&lifetime, "lifetime", 120*time.Second, "requested lease lifetime (kept short so leftovers expire fast)")
	cmd.Flags().StringVar(&protocol, "protocol", "auto", "protocol to use: auto (try all), pcp, natpmp, upnp")
	cmd.Flags().BoolVar(&keep, "keep", false, "leave the mapping in place instead of deleting it on exit")
	cmd.Flags().BoolVar(&verify, "verify", false, "start a temporary listener and test reachability through the external ip:port")
	cmd.Flags().BoolVar(&allowPrivileged, "allow-privileged", false, "allow ports below 1024")
	_ = cmd.MarkFlagRequired("port")
	return cmd
}

func newUnmapCmd(flags *rootFlags) *cobra.Command {
	var (
		portSpec        string
		allowPrivileged bool
	)
	cmd := &cobra.Command{
		Use:   "unmap --port 8080/tcp",
		Short: "Best-effort delete of a mapping on all protocols",
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec, gw, err := parseMapArgs(flags, portSpec, allowPrivileged)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			any := false
			for _, p := range []string{"pcp", "natpmp", "upnp"} {
				if err := probe.UnmapProtocol(ctx, p, gw, spec, flags.timeout); err != nil {
					fmt.Printf("%-8s delete failed: %v\n", p+":", err)
				} else {
					fmt.Printf("%-8s delete acknowledged\n", p+":")
					any = true
				}
			}
			if !any {
				fmt.Println("No protocol acknowledged the delete. If the mapping exists, it will expire when its lifetime runs out.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&portSpec, "port", "", "port to unmap, PORT/PROTO or EXT:INT/PROTO (e.g. 8080/tcp)")
	cmd.Flags().BoolVar(&allowPrivileged, "allow-privileged", false, "allow ports below 1024")
	_ = cmd.MarkFlagRequired("port")
	return cmd
}

func parseMapArgs(flags *rootFlags, portSpec string, allowPrivileged bool) (probe.Spec, probe.Gateway, error) {
	spec, err := probe.ParseSpec(portSpec)
	if err != nil {
		return probe.Spec{}, probe.Gateway{}, exitError{code: exitConfig, message: err.Error()}
	}
	if spec.Privileged() && !allowPrivileged {
		return probe.Spec{}, probe.Gateway{}, exitError{code: exitConfig, message: fmt.Sprintf("port spec %s uses a port below 1024 — probing well-known ports risks clobbering a real forwarding entry; pass --allow-privileged if you mean it", spec)}
	}
	gw, err := resolveGateway(flags)
	if err != nil {
		return probe.Spec{}, probe.Gateway{}, err
	}
	return spec, gw, nil
}

func printMapAttempt(a probe.MapAttempt, verbose bool) {
	status := verdictLabel(a.Verdict)
	if a.Lease != nil {
		lifetime := time.Duration(a.LifetimeSeconds) * time.Second
		fmt.Printf("%-8s %s — external %s, lifetime %s\n", a.Protocol+":", status, a.External, lifetime)
		if a.Remapped {
			fmt.Printf("%-8s %s\n", "", a.Detail)
		}
	} else {
		fmt.Printf("%-8s %s — %s\n", a.Protocol+":", status, a.Detail)
	}
	if verbose && len(a.Trace) > 0 {
		fmt.Printf("--- %s transcript ---\n", a.Protocol)
		printTrace(a.Trace)
	}
}
