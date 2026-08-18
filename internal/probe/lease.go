package probe

import (
	"net/netip"
	"time"
)

// Lease is one granted mapping, as reported by the gateway.
type Lease struct {
	Spec Spec `json:"-"`
	// External is the router-side address:port actually granted. The
	// address may be invalid when the gateway granted the port but its
	// external address could not be read.
	External netip.AddrPort `json:"external"`
	// Lifetime is the grant duration from the router.
	Lifetime time.Duration `json:"lifetime_ns"`
	// GrantedAt is when the grant was confirmed.
	GrantedAt time.Time `json:"granted_at"`
	// Protocol names which protocol granted it ("pcp", "nat-pmp", "upnp").
	Protocol string `json:"protocol"`
}

// Remapped reports whether the gateway granted a different external port
// than requested.
func (l Lease) Remapped() bool {
	return l.External.Port() != 0 && l.External.Port() != l.Spec.External
}
