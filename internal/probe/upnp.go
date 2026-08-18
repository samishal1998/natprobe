package probe

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ssdpMulticastAddr is the SSDP well-known multicast address, used in the
// M-SEARCH HOST header even for unicast searches.
const ssdpMulticastAddr = "239.255.255.250:1900"

// ssdpPort is where the unicast M-SEARCH goes on the gateway. A var so tests
// can point at a fake SSDP responder.
var ssdpPort uint16 = 1900

// wanServices are the service types usable for port mapping, tried in order;
// v2 first, v1 fallback covers old routers.
var wanServices = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// UPnPDevice is the diagnostic view of a discovered IGD.
type UPnPDevice struct {
	// Location is the SSDP LOCATION URL for the device description.
	Location string `json:"location"`
	// Server is the SSDP SERVER header (vendor/OS/UPnP stack version).
	Server string `json:"server,omitempty"`
	// FriendlyName, Manufacturer, ModelName come from the description XML.
	FriendlyName string `json:"friendly_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	// Services is every service in the device tree with its control URL.
	Services []UPnPService `json:"services"`

	// controlURL/serviceType are the resolved WAN*Connection endpoint.
	controlURL  *url.URL
	serviceType string
}

// UPnPService is one service entry from the device description.
type UPnPService struct {
	ServiceType string `json:"service_type"`
	ControlURL  string `json:"control_url"`
}

// WANService names the port-mapping service selected for SOAP calls, or ""
// when the device has none.
func (d *UPnPDevice) WANService() string { return d.serviceType }

// UPnPPortMapping is one row of the gateway's forwarding table.
type UPnPPortMapping struct {
	RemoteHost     string `json:"remote_host,omitempty"`
	ExternalPort   uint16 `json:"external_port"`
	Protocol       string `json:"protocol"`
	InternalPort   uint16 `json:"internal_port"`
	InternalClient string `json:"internal_client"`
	Enabled        bool   `json:"enabled"`
	Description    string `json:"description,omitempty"`
	LeaseSeconds   uint32 `json:"lease_seconds"`
}

// UPnPDiscover runs SSDP unicast discovery against the gateway and fetches
// the device description. Multicast is unreliable across OS firewalls; the
// gateway address is already known from the route table.
func UPnPDiscover(ctx context.Context, gw netip.Addr, timeout time.Duration, trace *Trace) (*UPnPDevice, error) {
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpMulticastAddr + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"\r\n"
	trace.Text("send", "SSDP M-SEARCH -> "+fmtAddrPort(gw, ssdpPort), search)
	resp, err := udpRoundTrip(ctx, gw, ssdpPort, []byte(search), timeout)
	if err != nil {
		trace.Notef("no SSDP answer: %v", err)
		return nil, err
	}
	trace.Text("recv", "SSDP response", string(resp))

	dev := &UPnPDevice{}
	for _, line := range strings.Split(string(resp), "\r\n") {
		// LOCATION: http://192.168.1.1:5000/rootDesc.xml — split on the
		// FIRST colon only; the URL keeps its own.
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "location":
			dev.Location = strings.TrimSpace(value)
		case "server":
			dev.Server = strings.TrimSpace(value)
		}
	}
	if dev.Location == "" {
		return nil, fmt.Errorf("%w: SSDP answered but the response had no LOCATION header", ErrUnsupported)
	}

	if err := dev.fetchDescription(ctx, timeout, trace); err != nil {
		return dev, err
	}
	return dev, nil
}

// igdDescription is the slice of the device XML we need. Devices nest
// recursively (IGD → WANDevice → WANConnectionDevice); services can hang off
// any level, so the walk below collects them all.
type igdDescription struct {
	URLBase string    `xml:"URLBase"`
	Device  igdDevice `xml:"device"`
}

type igdDevice struct {
	FriendlyName string       `xml:"friendlyName"`
	Manufacturer string       `xml:"manufacturer"`
	ModelName    string       `xml:"modelName"`
	Services     []igdService `xml:"serviceList>service"`
	DeviceList   []igdDevice  `xml:"deviceList>device"`
}

type igdService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func (d *UPnPDevice) fetchDescription(ctx context.Context, timeout time.Duration, trace *Trace) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.Location, nil)
	if err != nil {
		return fmt.Errorf("%w: bad LOCATION URL %q: %v", ErrUnsupported, d.Location, err)
	}
	trace.Text("send", "GET device description", req.Method+" "+d.Location)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		trace.Notef("description fetch failed: %v", err)
		return fmt.Errorf("%w: SSDP answered but the description fetch failed: %v", ErrUnsupported, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return fmt.Errorf("%w: reading device description: %v", ErrUnsupported, err)
	}
	trace.Text("recv", fmt.Sprintf("device description (HTTP %d, %d bytes)", resp.StatusCode, len(data)), string(data))

	var desc igdDescription
	if err := xml.Unmarshal(data, &desc); err != nil {
		return fmt.Errorf("%w: unparseable device description: %v", ErrUnsupported, err)
	}

	base, err := url.Parse(d.Location)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if desc.URLBase != "" {
		if b, err := url.Parse(desc.URLBase); err == nil {
			base = b
		}
	}

	d.FriendlyName = strings.TrimSpace(desc.Device.FriendlyName)
	d.Manufacturer = strings.TrimSpace(desc.Device.Manufacturer)
	d.ModelName = strings.TrimSpace(desc.Device.ModelName)

	// Collect every service in the tree, then pick the preferred WAN type.
	var walk func(dev igdDevice)
	walk = func(dev igdDevice) {
		for _, s := range dev.Services {
			resolved := s.ControlURL
			if u, err := url.Parse(s.ControlURL); err == nil {
				resolved = base.ResolveReference(u).String()
			}
			d.Services = append(d.Services, UPnPService{ServiceType: s.ServiceType, ControlURL: resolved})
		}
		for _, child := range dev.DeviceList {
			walk(child)
		}
	}
	walk(desc.Device)

	for _, want := range wanServices {
		for _, service := range d.Services {
			if service.ServiceType != want || service.ControlURL == "" {
				continue
			}
			control, err := url.Parse(service.ControlURL)
			if err != nil {
				continue
			}
			d.controlURL = control
			d.serviceType = service.ServiceType
			return nil
		}
	}
	return fmt.Errorf("%w: device description has no WANIPConnection/WANPPPConnection service (this device cannot do port mapping)", ErrUnsupported)
}

// ExternalIP asks the WAN service for the gateway's external IPv4.
func (d *UPnPDevice) ExternalIP(ctx context.Context, timeout time.Duration, trace *Trace) (netip.Addr, error) {
	if d.controlURL == nil {
		return netip.Addr{}, fmt.Errorf("%w: no WAN service", ErrUnsupported)
	}
	body := fmt.Sprintf(`<u:GetExternalIPAddress xmlns:u=%q></u:GetExternalIPAddress>`, d.serviceType)
	data, err := soap(ctx, d.controlURL, d.serviceType, "GetExternalIPAddress", body, timeout, trace)
	if err != nil {
		return netip.Addr{}, err
	}
	var parsed struct {
		IP string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return netip.Addr{}, fmt.Errorf("%w: unparseable GetExternalIPAddress response: %v", ErrUnsupported, err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(parsed.IP))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: gateway reported %q as its external address", ErrUnsupported, parsed.IP)
	}
	return addr, nil
}

// AddPortMapping requests a mapping. UPnP grants exactly the requested
// external port or errors (718 ConflictInMappingEntry) — no silent remap.
func (d *UPnPDevice) AddPortMapping(ctx context.Context, self netip.Addr, spec Spec, lifetime, timeout time.Duration, trace *Trace) (Lease, error) {
	if d.controlURL == nil {
		return Lease{}, fmt.Errorf("%w: no WAN service", ErrUnsupported)
	}
	body := fmt.Sprintf(`<u:AddPortMapping xmlns:u=%q><NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>natprobe</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration></u:AddPortMapping>`,
		d.serviceType, spec.External, strings.ToUpper(string(spec.Proto)), spec.Internal, self, int(lifetime.Seconds()))
	if _, err := soap(ctx, d.controlURL, d.serviceType, "AddPortMapping", body, timeout, trace); err != nil {
		return Lease{}, err
	}
	lease := Lease{
		Spec:      spec,
		Lifetime:  lifetime,
		GrantedAt: time.Now(),
		Protocol:  "upnp",
	}
	external, err := d.ExternalIP(ctx, timeout, trace)
	if err != nil {
		// The mapping exists; a failed external-IP read shouldn't lose it.
		external = netip.Addr{}
	}
	lease.External = netip.AddrPortFrom(external, spec.External)
	return lease, nil
}

// DeletePortMapping removes a mapping.
func (d *UPnPDevice) DeletePortMapping(ctx context.Context, spec Spec, timeout time.Duration, trace *Trace) error {
	if d.controlURL == nil {
		return fmt.Errorf("%w: no WAN service", ErrUnsupported)
	}
	body := fmt.Sprintf(`<u:DeletePortMapping xmlns:u=%q><NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol></u:DeletePortMapping>`,
		d.serviceType, spec.External, strings.ToUpper(string(spec.Proto)))
	_, err := soap(ctx, d.controlURL, d.serviceType, "DeletePortMapping", body, timeout, trace)
	return err
}

// ListPortMappings enumerates the gateway's forwarding table via
// GetGenericPortMappingEntry until UPnP error 713 (SpecifiedArrayIndexInvalid,
// end of list). Capped at 1000 entries to bound broken gateways.
func (d *UPnPDevice) ListPortMappings(ctx context.Context, timeout time.Duration, trace *Trace) ([]UPnPPortMapping, error) {
	if d.controlURL == nil {
		return nil, fmt.Errorf("%w: no WAN service", ErrUnsupported)
	}
	var mappings []UPnPPortMapping
	for index := 0; index < 1000; index++ {
		body := fmt.Sprintf(`<u:GetGenericPortMappingEntry xmlns:u=%q><NewPortMappingIndex>%d</NewPortMappingIndex></u:GetGenericPortMappingEntry>`, d.serviceType, index)
		data, err := soap(ctx, d.controlURL, d.serviceType, "GetGenericPortMappingEntry", body, timeout, trace)
		if err != nil {
			if strings.Contains(err.Error(), "713") {
				// SpecifiedArrayIndexInvalid: past the last entry.
				return mappings, nil
			}
			return mappings, err
		}
		var parsed struct {
			RemoteHost     string `xml:"Body>GetGenericPortMappingEntryResponse>NewRemoteHost"`
			ExternalPort   string `xml:"Body>GetGenericPortMappingEntryResponse>NewExternalPort"`
			Protocol       string `xml:"Body>GetGenericPortMappingEntryResponse>NewProtocol"`
			InternalPort   string `xml:"Body>GetGenericPortMappingEntryResponse>NewInternalPort"`
			InternalClient string `xml:"Body>GetGenericPortMappingEntryResponse>NewInternalClient"`
			Enabled        string `xml:"Body>GetGenericPortMappingEntryResponse>NewEnabled"`
			Description    string `xml:"Body>GetGenericPortMappingEntryResponse>NewPortMappingDescription"`
			LeaseDuration  string `xml:"Body>GetGenericPortMappingEntryResponse>NewLeaseDuration"`
		}
		if err := xml.Unmarshal(data, &parsed); err != nil {
			return mappings, fmt.Errorf("%w: unparseable GetGenericPortMappingEntry response: %v", ErrUnsupported, err)
		}
		ext, _ := strconv.ParseUint(strings.TrimSpace(parsed.ExternalPort), 10, 16)
		internal, _ := strconv.ParseUint(strings.TrimSpace(parsed.InternalPort), 10, 16)
		lease, _ := strconv.ParseUint(strings.TrimSpace(parsed.LeaseDuration), 10, 32)
		mappings = append(mappings, UPnPPortMapping{
			RemoteHost:     strings.TrimSpace(parsed.RemoteHost),
			ExternalPort:   uint16(ext),
			Protocol:       strings.TrimSpace(parsed.Protocol),
			InternalPort:   uint16(internal),
			InternalClient: strings.TrimSpace(parsed.InternalClient),
			Enabled:        strings.TrimSpace(parsed.Enabled) == "1",
			Description:    strings.TrimSpace(parsed.Description),
			LeaseSeconds:   uint32(lease),
		})
	}
	return mappings, nil
}

// soap performs one SOAP action, recording the full HTTP exchange in the
// trace.
func soap(ctx context.Context, control *url.URL, serviceType, action, innerBody string, timeout time.Duration, trace *Trace) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	envelope := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` +
		innerBody + `</s:Body></s:Envelope>`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, control.String(), strings.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, serviceType, action))
	trace.Text("send", "SOAP "+action+" -> "+control.String(), envelope)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var netErr net.Error
		if ctx.Err() != nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			return nil, fmt.Errorf("%w: %s got no answer within %s", ErrTimeout, action, timeout)
		}
		return nil, fmt.Errorf("%w: %s request failed: %v", ErrTimeout, action, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s response: %v", ErrUnsupported, action, err)
	}
	trace.Text("recv", fmt.Sprintf("SOAP %s response (HTTP %d)", action, resp.StatusCode), string(data))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered HTTP %d: %s", ErrUnsupported, action, resp.StatusCode, soapFaultString(data))
	}
	return data, nil
}

type soapFault struct {
	Code        string `xml:"Body>Fault>detail>UPnPError>errorCode"`
	Description string `xml:"Body>Fault>detail>UPnPError>errorDescription"`
}

func soapFaultString(data []byte) string {
	var f soapFault
	if err := xml.Unmarshal(data, &f); err != nil || f.Code == "" {
		return "unrecognized fault"
	}
	return fmt.Sprintf("UPnP error %s (%s)", f.Code, f.Description)
}
