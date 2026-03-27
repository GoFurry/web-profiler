package webprofiler

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"sort"
	"strings"
)

func analyzeFingerprint(r *http.Request, cfg FingerprintConfig, warnings *[]Warning) *FingerprintResult {
	fields := make(map[string]string, len(cfg.Headers)+4)

	for _, header := range cfg.Headers {
		if header == "host" {
			if value := normalizeFieldValue(r.Host); value != "" {
				fields["host"] = value
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
	}

	if cfg.IncludeTLS && r.TLS != nil {
		fields["tls.version"] = tlsVersionString(r.TLS.Version)
		if value := normalizeFieldValue(r.TLS.ServerName); value != "" {
			fields["tls.sni"] = value
		}
		if value := normalizeFieldValue(r.TLS.NegotiatedProtocol); value != "" {
			fields["tls.alpn"] = value
		}
	}

	if cfg.IncludeIP {
		if value := clientIP(r, cfg); value != "" {
			fields["client.ip"] = value
		}
	}

	algorithm := cfg.HashAlgorithm
	if algorithm != "sha256" {
		appendWarning(warnings, "fingerprint_hash_algorithm_fallback", "unsupported fingerprint hash algorithm, fallback to sha256")
		algorithm = "sha256"
	}

	return &FingerprintResult{
		Fields:        fields,
		Hash:          hashFields(fields, cfg.HashVersion),
		HashAlgorithm: algorithm,
		HashVersion:   cfg.HashVersion,
	}
}

func normalizeFieldValue(value string) string {
	if value == "" {
		return ""
	}

	parts := strings.Fields(strings.TrimSpace(value))
	return strings.ToLower(strings.Join(parts, " "))
}

func hashFields(fields map[string]string, version string) string {
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

	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func clientIP(r *http.Request, cfg FingerprintConfig) string {
	if cfg.TrustProxy {
		for _, header := range cfg.ProxyHeaders {
			value := strings.TrimSpace(r.Header.Get(header))
			if value == "" {
				continue
			}

			if header == "x-forwarded-for" {
				if idx := strings.IndexByte(value, ','); idx >= 0 {
					value = value[:idx]
				}
			}

			if host, _, err := net.SplitHostPort(strings.TrimSpace(value)); err == nil {
				return host
			}

			return strings.TrimSpace(value)
		}
	}

	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
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
