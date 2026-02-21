package tools

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// AnalyzeTLS connects directly to host:443 and inspects the TLS handshake.
// Uses InsecureSkipVerify so it captures data even from invalid/expired certs.
func AnalyzeTLS(host string) (*models.TLSInfo, error) {
	addr := net.JoinHostPort(host, "443")

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true, // intentional: we want to inspect bad certs too
			ServerName:         host,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates in TLS handshake")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	info := &models.TLSInfo{
		Host:       host,
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		Expiry:     cert.NotAfter,
		DaysLeft:   int(cert.NotAfter.Sub(now).Hours() / 24),
		Version:    tlsVersionName(state.Version),
		SelfSigned: cert.Issuer.CommonName == cert.Subject.CommonName,
		Expired:    now.After(cert.NotAfter),
		SANs:       cert.DNSNames,
	}

	return info, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// HasPort443 does a quick TCP check to see if port 443 is open on a host.
func HasPort443(host string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ExtractSANDomains returns all SAN domains from a TLS cert that belong to the target domain.
func ExtractSANDomains(info *models.TLSInfo, target string) []string {
	var result []string
	for _, san := range info.SANs {
		san = strings.TrimPrefix(san, "*.")
		if strings.HasSuffix(san, "."+target) || san == target {
			result = append(result, san)
		}
	}
	return result
}
