package probe

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Trace collects a wire-level transcript of one protocol conversation. It is
// the tool's soul: with -v every packet and HTTP exchange lands here, with
// field decoding annotations, so a failure is debuggable from the output
// alone. Safe for concurrent use (check probes protocols in parallel).
type Trace struct {
	mu      sync.Mutex
	entries []TraceEntry
}

// TraceEntry is one event in a transcript.
type TraceEntry struct {
	// At is when the event happened.
	At time.Time `json:"at"`
	// Dir is "send", "recv", or "note".
	Dir string `json:"dir"`
	// Label names the event, e.g. "NAT-PMP external-address request".
	Label string `json:"label"`
	// Detail is the rendered payload: an annotated hex dump for binary
	// protocols, raw HTTP text for UPnP, or a plain note.
	Detail string `json:"detail,omitempty"`
}

// Notef records a plain annotation.
func (t *Trace) Notef(format string, args ...any) {
	t.add(TraceEntry{At: time.Now(), Dir: "note", Label: fmt.Sprintf(format, args...)})
}

// Send records an outgoing binary packet with annotations.
func (t *Trace) Send(label string, packet []byte, annotations []string) {
	t.add(TraceEntry{At: time.Now(), Dir: "send", Label: label, Detail: renderPacket(packet, annotations)})
}

// Recv records an incoming binary packet with annotations.
func (t *Trace) Recv(label string, packet []byte, annotations []string) {
	t.add(TraceEntry{At: time.Now(), Dir: "recv", Label: label, Detail: renderPacket(packet, annotations)})
}

// Text records an outgoing or incoming text payload (HTTP/SOAP).
func (t *Trace) Text(dir, label, body string) {
	t.add(TraceEntry{At: time.Now(), Dir: dir, Label: label, Detail: strings.TrimRight(body, "\n")})
}

func (t *Trace) add(e TraceEntry) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append(t.entries, e)
}

// Entries returns a copy of the transcript in order.
func (t *Trace) Entries() []TraceEntry {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TraceEntry(nil), t.entries...)
}

// String renders the transcript for -v output.
func (t *Trace) String() string {
	var b strings.Builder
	for _, e := range t.Entries() {
		arrow := map[string]string{"send": ">>", "recv": "<<", "note": "--"}[e.Dir]
		fmt.Fprintf(&b, "%s %s %s\n", e.At.UTC().Format("2006-01-02T15:04:05.000Z"), arrow, e.Label)
		if e.Detail != "" {
			for _, line := range strings.Split(e.Detail, "\n") {
				fmt.Fprintf(&b, "    %s\n", line)
			}
		}
	}
	return b.String()
}

// renderPacket combines a hex dump with per-field decoding annotations.
func renderPacket(packet []byte, annotations []string) string {
	dump := HexDump(packet)
	if len(annotations) == 0 {
		return dump
	}
	return dump + "\n" + strings.Join(annotations, "\n")
}

// HexDump renders bytes as offset-prefixed hex with an ASCII gutter,
// 16 bytes per row:
//
//	0000  00 80 00 00 00 00 30 39  cb 00 71 02              ......09..q.
func HexDump(data []byte) string {
	if len(data) == 0 {
		return "(empty)"
	}
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		row := data[off:end]
		fmt.Fprintf(&b, "%04x  ", off)
		for i := 0; i < 16; i++ {
			if i == 8 {
				b.WriteByte(' ')
			}
			if off+i < end {
				fmt.Fprintf(&b, "%02x ", data[off+i])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteByte(' ')
		for _, c := range row {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		if end < len(data) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
