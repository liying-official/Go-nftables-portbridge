package proxy

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxConntrackRecords = 16384

type conntrackTuple struct {
	source, destination         netip.Addr
	sourcePort, destinationPort uint16
}

type conntrackEntry struct {
	family          int
	protocol        string
	original, reply conntrackTuple
	mark            uint32
	zone            uint16
}

type conntrackKernelIO interface {
	Available() error
	List(context.Context, nftRuleSpec) ([]conntrackEntry, error)
	ListOwned(context.Context, uint32) ([]conntrackEntry, error)
	Delete(context.Context, []conntrackEntry) error
}

type commandConntrack struct {
	binary  string
	initErr error
}

func newCommandConntrack() *commandConntrack {
	for _, path := range []string{"/usr/sbin/conntrack", "/usr/bin/conntrack"} {
		if trustedRootExecutable(path) {
			return &commandConntrack{binary: path}
		}
	}
	return &commandConntrack{initErr: errors.New("a trusted root-owned conntrack executable is required for nftables connection revocation")}
}
func (c *commandConntrack) Available() error { return c.initErr }

// Used only during recovery to detect unattributable old state. It never
// deletes anything and is not a substitute for per-rule tuple ownership.
func (c *commandConntrack) ListOwned(ctx context.Context, mark uint32) ([]conntrackEntry, error) {
	if mark == 0 {
		return nil, errors.New("invalid instance mark")
	}
	var result []conntrackEntry
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, protocol := range []string{"tcp", "udp"} {
			data, err := c.command(ctx, "", false, "-L", "-f", family, "-p", protocol, "--mark", fmt.Sprintf("0x%08x/0xffffffff", mark), "-o", "xml")
			if err != nil {
				return nil, err
			}
			entries, err := parseConntrackXML(data)
			if err != nil {
				return nil, err
			}
			if len(result)+len(entries) > maxConntrackRecords {
				return nil, errors.New("conntrack recovery exceeds record limit")
			}
			result = append(result, entries...)
		}
	}
	return result, nil
}

func (c *commandConntrack) List(ctx context.Context, spec nftRuleSpec) ([]conntrackEntry, error) {
	if err := validateRetirementSpec(spec); err != nil {
		return nil, err
	}
	family := "ipv4"
	if spec.Family == 6 {
		family = "ipv6"
	}
	args := []string{"-L", "-f", family, "-p", spec.Protocol, "--mark", fmt.Sprintf("0x%08x/0xffffffff", spec.ConntrackMark), "--reply-src", spec.TargetHost.String(), "-o", "xml"}
	if !spec.ListenHost.IsUnspecified() {
		args = append(args, "--orig-dst", spec.ListenHost.String())
	}
	if spec.ListenPortEnd == 0 || spec.ListenPortEnd == spec.ListenPort {
		args = append(args, "--dport", strconv.Itoa(spec.ListenPort))
	}
	data, err := c.command(ctx, "", false, args...)
	if err != nil {
		return nil, err
	}
	return parseConntrackXML(data)
}
func (c *commandConntrack) Delete(ctx context.Context, entries []conntrackEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) > maxConntrackRecords {
		return errors.New("conntrack retirement batch exceeds limit")
	}
	var lines strings.Builder
	for _, entry := range entries {
		args, err := conntrackDeleteArguments(entry)
		if err != nil {
			return err
		}
		lines.WriteString(strings.Join(args, " "))
		lines.WriteByte('\n')
	}
	_, err := c.command(ctx, lines.String(), true, "--load-file", "-")
	return err
}
func (c *commandConntrack) command(ctx context.Context, input string, discard bool, args ...string) ([]byte, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	cmd := exec.CommandContext(ctx, c.binary, args...) // #nosec G204 -- fixed trusted binary; arguments encode validated kernel tuples, never shell input.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(input)
	out := nftBoundedOutput{limit: maxNFTOutputBytes}
	errOut := nftBoundedOutput{limit: 64 << 10}
	cmd.Stdout = &out
	if discard {
		cmd.Stdout = io.Discard
	}
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("conntrack operation: %w", ctx.Err())
		}
		return nil, fmt.Errorf("conntrack operation failed: %w", err)
	}
	return out.Bytes(), nil
}

type conntrackXMLLayer3 struct {
	Name        string `xml:"protoname,attr"`
	Source      string `xml:"src"`
	Destination string `xml:"dst"`
}
type conntrackXMLLayer4 struct {
	Name        string `xml:"protoname,attr"`
	Source      string `xml:"sport"`
	Destination string `xml:"dport"`
}
type conntrackXMLMeta struct {
	Direction string             `xml:"direction,attr"`
	L3        conntrackXMLLayer3 `xml:"layer3"`
	L4        conntrackXMLLayer4 `xml:"layer4"`
	Mark      string             `xml:"mark"`
	Zone      string             `xml:"zone"`
}
type conntrackXMLFlow struct {
	Meta []conntrackXMLMeta `xml:"meta"`
}

func parseConntrackXML(data []byte) ([]conntrackEntry, error) {
	if len(data) > maxNFTOutputBytes {
		return nil, errors.New("conntrack inspection exceeds byte limit")
	}
	// conntrack 1.4.8 emits no XML at all for a successful zero-entry dump.
	// Command failures are checked by the caller before reaching this parser.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var entries []conntrackEntry
	root, closed := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !root || !closed {
				return nil, errors.New("missing or incomplete conntrack XML root")
			}
			return entries, nil
		}
		if err != nil {
			return nil, errors.New("invalid conntrack XML")
		}
		if end, ok := token.(xml.EndElement); ok {
			if end.Name.Local != "conntrack" || closed {
				return nil, errors.New("invalid conntrack XML end")
			}
			closed = true
			continue
		}
		if data, ok := token.(xml.CharData); ok && len(bytes.TrimSpace(data)) != 0 {
			return nil, errors.New("unexpected conntrack XML text")
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if closed {
			return nil, errors.New("trailing conntrack XML element")
		}
		if !root {
			if start.Name.Local != "conntrack" {
				return nil, errors.New("unexpected conntrack XML root")
			}
			root = true
			continue
		}
		if start.Name.Local != "flow" {
			return nil, errors.New("unexpected conntrack XML element")
		}
		if len(entries) >= maxConntrackRecords {
			return nil, errors.New("conntrack inspection exceeds record limit")
		}
		var flow conntrackXMLFlow
		if err := decoder.DecodeElement(&flow, &start); err != nil {
			return nil, errors.New("invalid conntrack flow")
		}
		entry, err := decodeConntrackFlow(flow)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
}
func decodeConntrackFlow(flow conntrackXMLFlow) (conntrackEntry, error) {
	var result conntrackEntry
	seen := make(map[string]bool, 3)
	for _, meta := range flow.Meta {
		if seen[meta.Direction] {
			return result, errors.New("duplicate conntrack direction")
		}
		seen[meta.Direction] = true
		switch meta.Direction {
		case "original", "reply":
			if meta.Zone != "" {
				return result, errors.New("direction-specific conntrack zones require explicit verification")
			}
			family := 0
			switch meta.L3.Name {
			case "ipv4":
				family = 4
			case "ipv6":
				family = 6
			default:
				return result, errors.New("invalid conntrack family")
			}
			if meta.L4.Name != "tcp" && meta.L4.Name != "udp" {
				return result, errors.New("invalid conntrack protocol")
			}
			if result.family != 0 && (result.family != family || result.protocol != meta.L4.Name) {
				return result, errors.New("inconsistent conntrack tuples")
			}
			result.family, result.protocol = family, meta.L4.Name
			source, err := netip.ParseAddr(strings.TrimSpace(meta.L3.Source))
			if err != nil || source.Zone() != "" {
				return result, errors.New("invalid conntrack source")
			}
			destination, err := netip.ParseAddr(strings.TrimSpace(meta.L3.Destination))
			if err != nil || destination.Zone() != "" {
				return result, errors.New("invalid conntrack destination")
			}
			if source.Is4() != (family == 4) || destination.Is4() != (family == 4) {
				return result, errors.New("conntrack tuple family mismatch")
			}
			sport, err := strconv.ParseUint(meta.L4.Source, 10, 16)
			if err != nil {
				return result, errors.New("invalid conntrack source port")
			}
			dport, err := strconv.ParseUint(meta.L4.Destination, 10, 16)
			if err != nil {
				return result, errors.New("invalid conntrack destination port")
			}
			tuple := conntrackTuple{source: source, destination: destination, sourcePort: uint16(sport), destinationPort: uint16(dport)}
			if meta.Direction == "original" {
				result.original = tuple
			} else {
				result.reply = tuple
			}
		case "independent":
			mark, err := strconv.ParseUint(meta.Mark, 10, 32)
			if err != nil {
				return result, errors.New("invalid conntrack mark")
			}
			result.mark = uint32(mark)
			if meta.Zone != "" {
				zone, err := strconv.ParseUint(meta.Zone, 10, 16)
				if err != nil {
					return result, errors.New("invalid conntrack zone")
				}
				result.zone = uint16(zone)
			}
		default:
			return result, errors.New("unknown conntrack direction")
		}
	}
	if !seen["original"] || !seen["reply"] || !seen["independent"] {
		return result, errors.New("incomplete conntrack tuples")
	}
	return result, nil
}

func validateRetirementSpec(spec nftRuleSpec) error {
	end := spec.ListenPortEnd
	if end == 0 {
		end = spec.ListenPort
	}
	targetEnd := spec.TargetPortEnd
	if targetEnd == 0 {
		targetEnd = spec.TargetPort
	}
	if (spec.Family != 4 && spec.Family != 6) || (spec.Protocol != "tcp" && spec.Protocol != "udp") || spec.ConntrackMark == 0 ||
		!spec.ListenHost.IsValid() || !spec.TargetHost.IsValid() || spec.ListenHost.Zone() != "" || spec.TargetHost.Zone() != "" ||
		spec.ListenHost.Is4() != (spec.Family == 4) || spec.TargetHost.Is4() != (spec.Family == 4) ||
		spec.ListenPort < 1 || end > 65535 || end < spec.ListenPort || spec.TargetPort < 1 || targetEnd > 65535 || targetEnd < spec.TargetPort ||
		end-spec.ListenPort != targetEnd-spec.TargetPort || end-spec.ListenPort+1 > 4096 {
		return errors.New("invalid nftables retirement identity")
	}
	return nil
}
func conntrackMatchesSpec(entry conntrackEntry, spec nftRuleSpec) bool {
	end := spec.ListenPortEnd
	if end == 0 {
		end = spec.ListenPort
	}
	port := int(entry.original.destinationPort)
	return entry.family == spec.Family && entry.protocol == spec.Protocol && entry.mark == spec.ConntrackMark &&
		(spec.ListenHost.IsUnspecified() || entry.original.destination == spec.ListenHost) &&
		port >= spec.ListenPort && port <= end && entry.reply.source == spec.TargetHost &&
		int(entry.reply.sourcePort) == spec.TargetPort+port-spec.ListenPort
}
func conntrackDeleteArguments(entry conntrackEntry) ([]string, error) {
	if entry.mark == 0 || (entry.family != 4 && entry.family != 6) || (entry.protocol != "tcp" && entry.protocol != "udp") {
		return nil, errors.New("invalid conntrack delete identity")
	}
	for _, address := range []netip.Addr{entry.original.source, entry.original.destination, entry.reply.source, entry.reply.destination} {
		if !address.IsValid() || address.Zone() != "" || address.Is4() != (entry.family == 4) {
			return nil, errors.New("invalid conntrack delete tuple")
		}
	}
	family := "ipv4"
	if entry.family == 6 {
		family = "ipv6"
	}
	return []string{"-D", "-f", family, "-p", entry.protocol,
		"--orig-src", entry.original.source.String(), "--orig-dst", entry.original.destination.String(),
		"--sport", strconv.Itoa(int(entry.original.sourcePort)), "--dport", strconv.Itoa(int(entry.original.destinationPort)),
		"--reply-src", entry.reply.source.String(), "--reply-dst", entry.reply.destination.String(),
		"--reply-port-src", strconv.Itoa(int(entry.reply.sourcePort)), "--reply-port-dst", strconv.Itoa(int(entry.reply.destinationPort)),
		"--mark", fmt.Sprintf("0x%08x/0xffffffff", entry.mark), "--zone", strconv.Itoa(int(entry.zone))}, nil
}

func revokeNFTConnections(kernel conntrackKernelIO, specs []nftRuleSpec) error {
	if len(specs) == 0 {
		return nil
	}
	if err := kernel.Available(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := kernel.List(ctx, spec)
		if err != nil {
			return err
		}
		selected := make([]conntrackEntry, 0, len(entries))
		for _, entry := range entries {
			if conntrackMatchesSpec(entry, spec) {
				selected = append(selected, entry)
			}
		}
		if len(selected) == 0 {
			continue
		}
		deleteErr := kernel.Delete(ctx, selected)
		if deleteErr != nil {
			var exit *exec.ExitError
			if !errors.As(deleteErr, &exit) || exit.ExitCode() != 1 {
				return deleteErr
			}
			// Exit 1 also means an entry expired concurrently; verify absence.
		}
		remaining, err := kernel.List(ctx, spec)
		if err != nil {
			return err
		}
		for _, entry := range remaining {
			if conntrackMatchesSpec(entry, spec) {
				return errors.New("matching conntrack entries remain; revocation incomplete")
			}
		}
	}
	return nil
}
