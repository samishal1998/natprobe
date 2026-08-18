// Command natprobe is a NAT traversal diagnostic CLI: it probes the LAN
// gateway's UPnP IGD, PCP, and NAT-PMP support and explains what it finds.
package main

import (
	"os"

	"github.com/samishal1998/natprobe/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
