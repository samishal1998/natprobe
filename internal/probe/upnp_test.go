package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeIGD serves a device description and a WANIPConnection control endpoint,
// including a canned port-mapping table for GetGenericPortMappingEntry.
type fakeIGD struct {
	server     *httptest.Server
	addCalls   []string
	delCalls   []string
	failAdd    string // UPnP error code to answer AddPortMapping with, "" = success
	externalIP string
	mappings   []UPnPPortMapping
}

func newFakeIGD(t *testing.T) *fakeIGD {
	t.Helper()
	igd := &fakeIGD{
		externalIP: "203.0.113.7",
		mappings: []UPnPPortMapping{
			{ExternalPort: 443, Protocol: "TCP", InternalPort: 443, InternalClient: "192.168.1.10", Enabled: true, Description: "https-server", LeaseSeconds: 0},
			{ExternalPort: 51820, Protocol: "UDP", InternalPort: 51820, InternalClient: "192.168.1.20", Enabled: true, Description: "wireguard", LeaseSeconds: 3600},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Test Router</friendlyName>
    <manufacturer>ACME</manufacturer>
    <modelName>WidgetRouter 3000</modelName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SOAPAction")
		switch {
		case strings.Contains(action, "AddPortMapping"):
			igd.addCalls = append(igd.addCalls, action)
			if igd.failAdd != "" {
				soapFaultResponse(w, igd.failAdd, "ConflictInMappingEntry")
				return
			}
			fmt.Fprint(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "DeletePortMapping"):
			igd.delCalls = append(igd.delCalls, action)
			fmt.Fprint(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:DeletePortMappingResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "GetExternalIPAddress"):
			fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, igd.externalIP)
		case strings.Contains(action, "GetGenericPortMappingEntry"):
			data, _ := io.ReadAll(r.Body)
			index := parseIndex(string(data))
			if index < 0 || index >= len(igd.mappings) {
				// 713 SpecifiedArrayIndexInvalid: end of list.
				soapFaultResponse(w, "713", "SpecifiedArrayIndexInvalid")
				return
			}
			m := igd.mappings[index]
			enabled := "0"
			if m.Enabled {
				enabled = "1"
			}
			fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost>%s</NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%s</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`,
				m.RemoteHost, m.ExternalPort, m.Protocol, m.InternalPort, m.InternalClient, enabled, m.Description, m.LeaseSeconds)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	igd.server = httptest.NewServer(mux)
	t.Cleanup(igd.server.Close)

	// SSDP responder: answers M-SEARCH with the description LOCATION.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			_, remote, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := "HTTP/1.1 200 OK\r\n" +
				"LOCATION: " + igd.server.URL + "/rootDesc.xml\r\n" +
				"SERVER: FakeOS/1.0 UPnP/1.1 FakeIGD/2.0\r\n" +
				"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
			if _, err := udp.WriteToUDP([]byte(resp), remote); err != nil {
				return
			}
		}
	}()
	local := udp.LocalAddr().(*net.UDPAddr)
	swapSSDPPort(t, uint16(local.Port))
	return igd
}

func soapFaultResponse(w http.ResponseWriter, code, description string) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>%s</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, description)
}

// parseIndex pulls NewPortMappingIndex out of a request body without a full
// XML parse (the fake only needs the number).
func parseIndex(body string) int {
	const open, close = "<NewPortMappingIndex>", "</NewPortMappingIndex>"
	i := strings.Index(body, open)
	j := strings.Index(body, close)
	if i < 0 || j < 0 || j <= i+len(open) {
		return -1
	}
	var n int
	if _, err := fmt.Sscanf(body[i+len(open):j], "%d", &n); err != nil {
		return -1
	}
	return n
}

// swapSSDPPort points UPnP discovery at a fake SSDP responder for one test.
func swapSSDPPort(t *testing.T, port uint16) {
	t.Helper()
	orig := ssdpPort
	ssdpPort = port
	t.Cleanup(func() { ssdpPort = orig })
}

func TestUPnPDiscoverReadsDeviceInfo(t *testing.T) {
	newFakeIGD(t)

	dev, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if dev.FriendlyName != "Test Router" || dev.Manufacturer != "ACME" || dev.ModelName != "WidgetRouter 3000" {
		t.Errorf("device info: %+v", dev)
	}
	if !strings.Contains(dev.Server, "FakeIGD/2.0") {
		t.Errorf("SERVER header: %q", dev.Server)
	}
	if dev.WANService() != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Errorf("WAN service: %s", dev.WANService())
	}
	if len(dev.Services) != 1 {
		t.Errorf("services: %+v", dev.Services)
	}
}

func TestUPnPExternalIP(t *testing.T) {
	newFakeIGD(t)
	dev, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := dev.ExternalIP(context.Background(), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if addr != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("external = %s", addr)
	}
}

func TestUPnPAddAndDeletePortMapping(t *testing.T) {
	igd := newFakeIGD(t)
	dev, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{Internal: 8080, External: 8080, Proto: TCP}
	lease, err := dev.AddPortMapping(context.Background(), testSelf, spec, 120*time.Second, testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if lease.External.String() != "203.0.113.7:8080" {
		t.Errorf("lease external = %s", lease.External)
	}
	if len(igd.addCalls) != 1 {
		t.Errorf("AddPortMapping calls: %d", len(igd.addCalls))
	}
	if err := dev.DeletePortMapping(context.Background(), spec, testTimeout, &Trace{}); err != nil {
		t.Fatal(err)
	}
	if len(igd.delCalls) != 1 {
		t.Errorf("DeletePortMapping calls: %d", len(igd.delCalls))
	}
}

func TestUPnPAddFailureSurfacesFaultCode(t *testing.T) {
	igd := newFakeIGD(t)
	igd.failAdd = "718"
	dev, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dev.AddPortMapping(context.Background(), testSelf, Spec{Internal: 8080, External: 8080, Proto: TCP}, 120*time.Second, testTimeout, &Trace{})
	if err == nil || !strings.Contains(err.Error(), "718") {
		t.Errorf("the UPnP fault code must reach the error, got %v", err)
	}
}

func TestUPnPListPortMappingsEnumeratesUntil713(t *testing.T) {
	newFakeIGD(t)
	dev, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := dev.ListPortMappings(context.Background(), testTimeout, &Trace{})
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mappings: %+v", mappings)
	}
	if mappings[0].ExternalPort != 443 || mappings[0].Description != "https-server" || !mappings[0].Enabled {
		t.Errorf("first mapping: %+v", mappings[0])
	}
	if mappings[1].Protocol != "UDP" || mappings[1].LeaseSeconds != 3600 {
		t.Errorf("second mapping: %+v", mappings[1])
	}
}

func TestUPnPTimeoutWhenNoSSDPResponder(t *testing.T) {
	swapSSDPPort(t, 1)
	_, err := UPnPDiscover(context.Background(), netip.MustParseAddr("127.0.0.1"), 500*time.Millisecond, &Trace{})
	if Classify(err) != VerdictTimeout {
		t.Errorf("want timeout verdict, got %v (%s)", err, Classify(err))
	}
}
