package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/samishal1998/natprobe/internal/probe"
)

// gatewayReport is the --json schema for natprobe gateway.
type gatewayReport struct {
	// CheckedAt is when the discovery ran (ISO 8601).
	CheckedAt time.Time `json:"checked_at"`
	// Gateway/Self/Interface come from the route table.
	Gateway   string `json:"gateway"`
	Self      string `json:"self"`
	Interface string `json:"interface,omitempty"`
	// AnswersNATPMPPort is true when 5351/udp answered a NAT-PMP
	// external-address request; AnswersSSDPPort when 1900/udp answered an
	// SSDP M-SEARCH.
	AnswersNATPMPPort bool `json:"answers_5351_udp"`
	AnswersSSDPPort   bool `json:"answers_1900_udp"`
}

func newGatewayCmd(flags *rootFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Discover the LAN gateway and see whether it answers on the NAT traversal ports",
		RunE: func(cmd *cobra.Command, _ []string) error {
			gw, err := resolveGateway(flags)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			// 5351/udp: a NAT-PMP external-address request is a harmless
			// read; any answer (even an error) proves a listener.
			natpmpProbe := []byte{0, 0}
			// 1900/udp: an SSDP M-SEARCH for the IGD root device.
			ssdpProbe := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")

			report := gatewayReport{
				CheckedAt:         time.Now().UTC(),
				Gateway:           gw.Addr.String(),
				Self:              renderAddr(gw.Self),
				Interface:         gw.Interface,
				AnswersNATPMPPort: probe.UDPProbe(ctx, gw.Addr, 5351, natpmpProbe, flags.timeout),
				AnswersSSDPPort:   probe.UDPProbe(ctx, gw.Addr, 1900, ssdpProbe, flags.timeout),
			}

			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(report)
			}

			fmt.Printf("Gateway:    %s\n", report.Gateway)
			fmt.Printf("Own addr:   %s\n", report.Self)
			if report.Interface != "" {
				fmt.Printf("Interface:  %s\n", report.Interface)
			}
			fmt.Printf("5351/udp:   %s\n", answerText(report.AnswersNATPMPPort, "NAT-PMP/PCP port answered", "no answer — NAT-PMP/PCP disabled or not supported"))
			fmt.Printf("1900/udp:   %s\n", answerText(report.AnswersSSDPPort, "SSDP port answered", "no answer — UPnP disabled or not supported"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	return cmd
}

func answerText(ok bool, yes, no string) string {
	if ok {
		return "✓ " + yes
	}
	return "✗ " + no
}

func renderAddr(a interface{ String() string }) string {
	s := a.String()
	if s == "invalid IP" {
		return "unknown"
	}
	return s
}
