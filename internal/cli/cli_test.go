package cli

import (
	"strings"
	"testing"
)

func TestMapProtocolsExpansion(t *testing.T) {
	got, err := mapProtocols("auto")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "pcp,natpmp,upnp" {
		t.Errorf("auto = %v", got)
	}
	for _, p := range []string{"pcp", "natpmp", "upnp"} {
		got, err := mapProtocols(p)
		if err != nil || len(got) != 1 || got[0] != p {
			t.Errorf("mapProtocols(%q) = %v, %v", p, got, err)
		}
	}
	if _, err := mapProtocols("teredo"); err == nil {
		t.Error("unknown protocol must be rejected")
	}
}

func TestPrivilegedPortRefusedWithoutFlag(t *testing.T) {
	flags := &rootFlags{}
	_, _, err := parseMapArgs(flags, "443/tcp", false)
	var coded exitError
	if !asExitError(err, &coded) || coded.code != exitConfig {
		t.Fatalf("privileged port without --allow-privileged must be a config error (exit 2), got %v", err)
	}
	if !strings.Contains(coded.message, "--allow-privileged") {
		t.Errorf("the refusal must name the unblock flag: %q", coded.message)
	}
}

func TestBadPortSpecIsConfigError(t *testing.T) {
	flags := &rootFlags{}
	_, _, err := parseMapArgs(flags, "not-a-port", false)
	var coded exitError
	if !asExitError(err, &coded) || coded.code != exitConfig {
		t.Fatalf("bad spec must be a config error (exit 2), got %v", err)
	}
}
