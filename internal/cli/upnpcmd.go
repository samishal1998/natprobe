package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/samishal1998/natprobe/internal/probe"
)

func newUpnpCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upnp",
		Short: "UPnP-specific diagnostics",
	}
	cmd.AddCommand(newUpnpDescribeCmd(flags))
	return cmd
}

func newUpnpDescribeCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe",
		Short: "Dump the IGD device description and the existing port-mapping table",
		Long:  "Discovers the gateway's UPnP IGD via SSDP, dumps the device description (friendlyName, manufacturer, model, service list with control URLs), and enumerates the router's existing port-mapping table via GetGenericPortMappingEntry — a view of what is already forwarded.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			gw, err := resolveGateway(flags)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			trace := &probe.Trace{}
			dev, discErr := probe.UPnPDiscover(ctx, gw.Addr, flags.timeout, trace)
			if dev == nil {
				if flags.verbose {
					printTrace(trace.Entries())
				}
				return exitError{code: exitFailed, message: fmt.Sprintf("UPnP discovery failed: %v", discErr)}
			}

			fmt.Printf("SSDP LOCATION:  %s\n", dev.Location)
			if dev.Server != "" {
				fmt.Printf("SSDP SERVER:    %s\n", dev.Server)
			}
			if dev.FriendlyName != "" {
				fmt.Printf("Friendly name:  %s\n", dev.FriendlyName)
			}
			if dev.Manufacturer != "" {
				fmt.Printf("Manufacturer:   %s\n", dev.Manufacturer)
			}
			if dev.ModelName != "" {
				fmt.Printf("Model:          %s\n", dev.ModelName)
			}
			if len(dev.Services) > 0 {
				fmt.Println("\nServices:")
				for _, s := range dev.Services {
					marker := " "
					if s.ServiceType == dev.WANService() {
						marker = "*"
					}
					fmt.Printf("  %s %s\n      control: %s\n", marker, s.ServiceType, s.ControlURL)
				}
				if dev.WANService() != "" {
					fmt.Println("  (* = service used for port mapping)")
				}
			}
			if discErr != nil {
				if flags.verbose {
					printTrace(trace.Entries())
				}
				return exitError{code: exitFailed, message: discErr.Error()}
			}

			mappings, err := dev.ListPortMappings(ctx, flags.timeout, trace)
			if err != nil && len(mappings) == 0 {
				fmt.Printf("\nCould not enumerate the port-mapping table: %v\n", err)
			} else {
				fmt.Printf("\nExisting port mappings (%d):\n", len(mappings))
				if len(mappings) > 0 {
					fmt.Printf("  %-7s %-6s %-22s %-8s %-9s %s\n", "EXT", "PROTO", "INTERNAL", "ENABLED", "LEASE", "DESCRIPTION")
					for _, m := range mappings {
						lease := "static"
						if m.LeaseSeconds > 0 {
							lease = (time.Duration(m.LeaseSeconds) * time.Second).String()
						}
						enabled := "no"
						if m.Enabled {
							enabled = "yes"
						}
						fmt.Printf("  %-7d %-6s %-22s %-8s %-9s %s\n", m.ExternalPort, m.Protocol, fmt.Sprintf("%s:%d", m.InternalClient, m.InternalPort), enabled, lease, m.Description)
					}
				}
			}

			if flags.verbose {
				fmt.Println("\n--- upnp transcript ---")
				printTrace(trace.Entries())
			}
			return nil
		},
	}
	return cmd
}
