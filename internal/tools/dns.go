package tools

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

var resolver = &net.Resolver{
	PreferGo: true,
}

// ResolveDNS resolves A, CNAME, MX, and TXT records for a hostname.
// Uses Go's built-in net package — no external tool required.
func ResolveDNS(host string) []models.DNSRecord {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var records []models.DNSRecord

	// A records
	addrs, err := resolver.LookupHost(ctx, host)
	if err == nil {
		for _, addr := range addrs {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "A",
				Value: addr,
			})
		}
	}

	// CNAME
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != host+"." && cname != "" {
		records = append(records, models.DNSRecord{
			Host:  host,
			Type:  "CNAME",
			Value: cname,
		})
	}

	// MX
	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil {
		for _, mx := range mxRecords {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "MX",
				Value: mx.Host,
			})
		}
	}

	// TXT
	txtRecords, err := resolver.LookupTXT(ctx, host)
	if err == nil {
		for _, txt := range txtRecords {
			records = append(records, models.DNSRecord{
				Host:  host,
				Type:  "TXT",
				Value: txt,
			})
		}
	}

	return records
}

// ── Zone Transfer (AXFR) ─────────────────────────────────────────────────────

// DNS record type constants (RFC 1035 / 3596).
const (
	dnsTypeA    = 1
	dnsTypeNS   = 2
	dnsTypeCNAME = 5
	dnsTypeSOA  = 6
	dnsTypeMX   = 15
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeAXFR = 252
)

// TryZoneTransfers attempts a DNS zone transfer (AXFR) against every nameserver
// for the given domain. Returns the discovered records and true if any transfer
// succeeded. Most authoritative nameservers refuse AXFR; this is a low-effort
// probe that produces high-value data when it works.
func TryZoneTransfers(domain string) ([]models.DNSRecord, bool) {
	nses, err := net.LookupNS(domain)
	if err != nil || len(nses) == 0 {
		return nil, false
	}

	for _, ns := range nses {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		records, err := axfrQuery(domain, nsHost)
		if err == nil && len(records) > 0 {
			return records, true
		}
	}
	return nil, false
}

// axfrQuery performs a raw DNS AXFR query over TCP against a single nameserver.
func axfrQuery(domain, ns string) ([]models.DNSRecord, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ns, "53"), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", ns, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck

	query := buildAXFRQuery(domain)

	// TCP DNS: 2-byte big-endian length prefix followed by message bytes.
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	if _, err := conn.Write(append(lenBuf, query...)); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	var records []models.DNSRecord
	soaCount := 0

	for {
		// Read 2-byte length prefix of the next DNS message.
		var msgLen uint16
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("read length: %w", err)
		}

		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			break
		}

		recs, soaInMsg, err := parseDNSResponse(buf)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		records = append(records, recs...)
		soaCount += soaInMsg

		// AXFR transfer is terminated by two SOA records (RFC 5936).
		if soaCount >= 2 {
			break
		}
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no records received from %s", ns)
	}
	return records, nil
}

// buildAXFRQuery constructs a raw DNS AXFR query message (without TCP length prefix).
func buildAXFRQuery(domain string) []byte {
	var msg []byte
	// Header (12 bytes)
	msg = append(msg, 0x04, 0xD2) // Transaction ID = 1234
	msg = append(msg, 0x00, 0x00) // Flags: standard query, RD=0
	msg = append(msg, 0x00, 0x01) // QDCOUNT = 1
	msg = append(msg, 0x00, 0x00) // ANCOUNT = 0
	msg = append(msg, 0x00, 0x00) // NSCOUNT = 0
	msg = append(msg, 0x00, 0x00) // ARCOUNT = 0

	// Question section: QNAME (label format)
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)       // root label terminator
	msg = append(msg, 0x00, 0xFC) // QTYPE = AXFR (252)
	msg = append(msg, 0x00, 0x01) // QCLASS = IN

	return msg
}

// parseDNSResponse parses a single DNS response message and extracts resource records.
// Returns the records, the number of SOA records encountered, and any parse error.
func parseDNSResponse(buf []byte) ([]models.DNSRecord, int, error) {
	if len(buf) < 12 {
		return nil, 0, fmt.Errorf("message too short (%d bytes)", len(buf))
	}

	// Check response code (RCODE in lower 4 bits of byte 3)
	rcode := int(buf[3]) & 0x0F
	if rcode != 0 {
		return nil, 0, fmt.Errorf("DNS RCODE=%d (refused or not authoritative)", rcode)
	}

	qdcount := int(binary.BigEndian.Uint16(buf[4:6]))
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))

	offset := 12 // skip header

	// Skip question section
	for i := 0; i < qdcount; i++ {
		var err error
		_, offset, err = parseDNSName(buf, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("question name: %w", err)
		}
		offset += 4 // QTYPE (2) + QCLASS (2)
	}

	var records []models.DNSRecord
	soaCount := 0

	for i := 0; i < ancount; i++ {
		if offset >= len(buf) {
			break
		}

		rrName, newOffset, err := parseDNSName(buf, offset)
		if err != nil {
			break
		}
		offset = newOffset

		if offset+10 > len(buf) {
			break
		}

		rrType := binary.BigEndian.Uint16(buf[offset:])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdlength := int(binary.BigEndian.Uint16(buf[offset:]))
		offset += 2 // RDLENGTH

		if offset+rdlength > len(buf) {
			break
		}
		rdataStart := offset
		offset += rdlength

		switch rrType {
		case dnsTypeA:
			if rdlength == 4 {
				records = append(records, models.DNSRecord{
					Host: rrName, Type: "A",
					Value: net.IP(buf[rdataStart : rdataStart+4]).String(),
				})
			}
		case dnsTypeAAAA:
			if rdlength == 16 {
				records = append(records, models.DNSRecord{
					Host: rrName, Type: "AAAA",
					Value: net.IP(buf[rdataStart : rdataStart+16]).String(),
				})
			}
		case dnsTypeCNAME:
			if name, _, err := parseDNSName(buf, rdataStart); err == nil {
				records = append(records, models.DNSRecord{Host: rrName, Type: "CNAME", Value: name})
			}
		case dnsTypeNS:
			if name, _, err := parseDNSName(buf, rdataStart); err == nil {
				records = append(records, models.DNSRecord{Host: rrName, Type: "NS", Value: name})
			}
		case dnsTypeMX:
			if rdlength >= 3 {
				if name, _, err := parseDNSName(buf, rdataStart+2); err == nil {
					records = append(records, models.DNSRecord{Host: rrName, Type: "MX", Value: name})
				}
			}
		case dnsTypeTXT:
			var parts []string
			i := rdataStart
			for i < rdataStart+rdlength {
				l := int(buf[i])
				i++
				if i+l > rdataStart+rdlength {
					break
				}
				parts = append(parts, string(buf[i:i+l]))
				i += l
			}
			records = append(records, models.DNSRecord{Host: rrName, Type: "TXT", Value: strings.Join(parts, " ")})
		case dnsTypeSOA:
			soaCount++
		}
	}

	return records, soaCount, nil
}

// parseDNSName parses a DNS name at the given offset within buf, following
// RFC 1035 pointer compression. Returns the name, the offset after the name
// in the original message (not following pointers), and any error.
func parseDNSName(buf []byte, offset int) (string, int, error) {
	var labels []string
	origOffset := -1 // saves the offset right after the pointer bytes
	visited := make(map[int]bool)

	for {
		if offset >= len(buf) {
			return "", 0, fmt.Errorf("DNS name truncated at offset %d", offset)
		}
		if visited[offset] {
			return "", 0, fmt.Errorf("DNS name pointer loop at offset %d", offset)
		}
		visited[offset] = true

		b := buf[offset]

		if b == 0 {
			// Root label — end of name
			if origOffset == -1 {
				origOffset = offset + 1
			}
			return strings.Join(labels, "."), origOffset, nil
		}

		if b&0xC0 == 0xC0 {
			// Pointer: 14-bit offset
			if offset+1 >= len(buf) {
				return "", 0, fmt.Errorf("DNS pointer truncated at offset %d", offset)
			}
			if origOffset == -1 {
				origOffset = offset + 2 // advance past the 2-byte pointer
			}
			offset = int(b&0x3F)<<8 | int(buf[offset+1])
			continue
		}

		// Regular label: b is the length
		length := int(b)
		offset++
		if offset+length > len(buf) {
			return "", 0, fmt.Errorf("DNS label truncated at offset %d", offset)
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}
}

// ResolveIP returns the first IPv4 address for a hostname, or empty string.
func ResolveIP(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}
