package core

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

func analyzeFingerprint(r *http.Request, cfg FingerprintConfig, warnings *[]Warning) *FingerprintResult {
	fields := make(map[string]string, len(cfg.Headers)+4)
	weakFields := make(map[string]string, len(cfg.Headers)+3)
	sourceFlags := make([]string, 0, 3)
	headersAdded := false

	for _, header := range cfg.Headers {
		if header == "host" {
			if value := normalizeFieldValue(r.Host); value != "" {
				fields["host"] = value
				weakFields["host"] = value
				headersAdded = true
			}
			continue
		}

		values := r.Header.Values(header)
		if len(values) == 0 {
			continue
		}

		value := normalizeFieldValue(strings.Join(values, ","))
		if value == "" {
			continue
		}

		fields[header] = value
		weakFields[header] = value
		headersAdded = true
	}
	if headersAdded {
		sourceFlags = append(sourceFlags, "headers")
	}

	if cfg.IncludeTLS && r.TLS != nil {
		tlsAdded := false
		fields["tls.version"] = tlsVersionString(r.TLS.Version)
		weakFields["tls.version"] = fields["tls.version"]
		tlsAdded = true
		if value := normalizeFieldValue(r.TLS.ServerName); value != "" {
			fields["tls.sni"] = value
			weakFields["tls.sni"] = value
			tlsAdded = true
		}
		if value := normalizeFieldValue(r.TLS.NegotiatedProtocol); value != "" {
			fields["tls.alpn"] = value
			weakFields["tls.alpn"] = value
			tlsAdded = true
		}
		if tlsAdded {
			sourceFlags = append(sourceFlags, "tls")
		}
	}

	if cfg.IncludeIP {
		if value := clientIP(r, cfg); value != "" {
			fields["client.ip"] = value
			sourceFlags = append(sourceFlags, "ip")
		}
	}

	algorithm := cfg.HashAlgorithm
	if !isSupportedHashAlgorithm(algorithm) {
		appendWarning(warnings, "fingerprint_hash_algorithm_fallback", "unsupported fingerprint hash algorithm, fallback to sha256")
		algorithm = "sha256"
	}

	strongHash := hashFields(fields, cfg.HashVersion, algorithm)
	weakHash := hashFields(weakFields, cfg.HashVersion, algorithm)
	if weakHash == "" {
		weakHash = strongHash
	}

	result := &FingerprintResult{
		SourceFlags:   append([]string(nil), sourceFlags...),
		Hash:          strongHash,
		WeakHash:      weakHash,
		StrongHash:    strongHash,
		HashAlgorithm: algorithm,
		HashVersion:   cfg.HashVersion,
	}
	if cfg.ExposeFields {
		result.Fields = fields
	}

	return result
}

func normalizeFieldValue(value string) string {
	if value == "" {
		return ""
	}

	parts := strings.Fields(strings.TrimSpace(value))
	return strings.ToLower(strings.Join(parts, " "))
}

func hashFields(fields map[string]string, version, algorithm string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString(version)
	builder.WriteByte('\n')
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(fields[key])
		builder.WriteByte('\n')
	}

	return hashString(builder.String(), algorithm)
}

func hashString(value, algorithm string) string {
	switch algorithm {
	case "sha1":
		sum := sha1.Sum([]byte(value))
		return hex.EncodeToString(sum[:])
	case "sha256":
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	case "sha512":
		sum := sha512.Sum512([]byte(value))
		return hex.EncodeToString(sum[:])
	case "fnv1a64":
		hasher := fnv.New64a()
		_, _ = hasher.Write([]byte(value))
		return hex.EncodeToString(hasher.Sum(nil))
	default:
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
}

func isSupportedHashAlgorithm(algorithm string) bool {
	switch algorithm {
	case "sha1", "sha256", "sha512", "fnv1a64":
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request, cfg FingerprintConfig) string {
	if shouldTrustProxyHeaders(r, cfg) {
		for _, header := range cfg.ProxyHeaders {
			value := strings.TrimSpace(r.Header.Get(header))
			if value == "" {
				continue
			}

			switch header {
			case "forwarded":
				value = forwardedForValue(value)
			case "x-forwarded-for":
				if idx := strings.IndexByte(value, ','); idx >= 0 {
					value = value[:idx]
				}
			}

			if ip, ok := parseNormalizedIP(value); ok {
				return ip
			}
		}
	}

	if ip, ok := parseNormalizedIP(r.RemoteAddr); ok {
		return ip
	}

	return ""
}

func forwardedForValue(headerValue string) string {
	for _, fieldValue := range strings.Split(headerValue, ",") {
		pairs := strings.Split(fieldValue, ";")
		for _, pair := range pairs {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			if strings.ToLower(strings.TrimSpace(key)) != "for" {
				continue
			}

			value = strings.TrimSpace(strings.Trim(value, `"`))
			if value == "" || strings.HasPrefix(value, "_") {
				return ""
			}
			return value
		}
	}

	return ""
}

func shouldTrustProxyHeaders(r *http.Request, cfg FingerprintConfig) bool {
	if !cfg.TrustProxy {
		return false
	}
	if len(cfg.TrustedProxyCIDRs) == 0 {
		return true
	}

	remoteIP := remoteAddrIP(r.RemoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, cidr := range cfg.TrustedProxyCIDRs {
		if containsIP(cidr, remoteIP) {
			return true
		}
	}

	return false
}

func remoteAddrIP(remoteAddr string) net.IP {
	if normalized, ok := parseNormalizedIP(remoteAddr); ok {
		return net.ParseIP(normalized)
	}
	return nil
}

func containsIP(cidr string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	if parsedIP := net.ParseIP(cidr); parsedIP != nil {
		return parsedIP.Equal(ip)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func tlsVersionString(version uint16) string {
	switch version {
	case 0x0301:
		return "tls1.0"
	case 0x0302:
		return "tls1.1"
	case 0x0303:
		return "tls1.2"
	case 0x0304:
		return "tls1.3"
	default:
		return "unknown"
	}
}

func parseNormalizedIP(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.String(), true
	}

	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort.Addr().String(), true
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
			return addr.String(), true
		}
	}

	return "", false
}
