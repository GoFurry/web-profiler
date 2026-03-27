package webprofiler

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestAnalyzeFingerprintNormalizesInputsAndBuildsStableHash(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/login", nil)
	req.Host = "Example.COM:443"
	req.Header.Set("User-Agent", "  Fancy   Client/1.0  ")
	req.Header.Set("Accept-Language", "en-US, zh-CN")
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.7")
	req.RemoteAddr = "192.0.2.10:9000"
	req.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		ServerName:         "API.Example.com",
		NegotiatedProtocol: "h2",
	}

	var warnings []Warning
	result := analyzeFingerprint(req, FingerprintConfig{
		Headers:       []string{"host", "user-agent", "accept-language"},
		IncludeIP:     true,
		IncludeTLS:    true,
		TrustProxy:    true,
		ProxyHeaders:  []string{"x-forwarded-for"},
		HashAlgorithm: "sha256",
		HashVersion:   "v2",
	}, &warnings)

	if result == nil {
		t.Fatal("expected fingerprint result")
	}

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	wantFields := map[string]string{
		"accept-language": "en-us, zh-cn",
		"client.ip":       "198.51.100.20",
		"host":            "example.com:443",
		"tls.alpn":        "h2",
		"tls.sni":         "api.example.com",
		"tls.version":     "tls1.3",
		"user-agent":      "fancy client/1.0",
	}

	if len(result.Fields) != len(wantFields) {
		t.Fatalf("unexpected number of fingerprint fields: got %d want %d (%v)", len(result.Fields), len(wantFields), result.Fields)
	}

	for key, want := range wantFields {
		if got := result.Fields[key]; got != want {
			t.Fatalf("unexpected fingerprint field %q: got %q want %q", key, got, want)
		}
	}

	if result.HashAlgorithm != "sha256" {
		t.Fatalf("unexpected hash algorithm: got %q want %q", result.HashAlgorithm, "sha256")
	}

	if result.HashVersion != "v2" {
		t.Fatalf("unexpected hash version: got %q want %q", result.HashVersion, "v2")
	}

	if result.Hash != hashFields(result.Fields, "v2") {
		t.Fatalf("fingerprint hash should be reproducible, got %q", result.Hash)
	}
}

func TestAnalyzeFingerprintFallsBackToSHA256(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ping", nil)

	var warnings []Warning
	result := analyzeFingerprint(req, FingerprintConfig{
		Headers:       []string{"host"},
		HashAlgorithm: "md5",
		HashVersion:   "v1",
	}, &warnings)

	if result == nil {
		t.Fatal("expected fingerprint result")
	}

	if result.HashAlgorithm != "sha256" {
		t.Fatalf("unsupported hash algorithms should fall back to sha256, got %q", result.HashAlgorithm)
	}

	if !hasWarningCode(warnings, "fingerprint_hash_algorithm_fallback") {
		t.Fatalf("expected fingerprint_hash_algorithm_fallback warning, got %+v", warnings)
	}
}

func TestAnalyzeComplexityJSONStats(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		observed:    []byte(`{"a":[{"b":1},{"c":2}],"d":{"e":3}}`),
		analyzed:    true,
	}

	var warnings []Warning
	result := analyzeComplexity(sample, DefaultConfig().Complexity, &warnings)

	if result == nil {
		t.Fatal("expected complexity result")
	}

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	if result.ContentType != "application/json" {
		t.Fatalf("unexpected content type: got %q want %q", result.ContentType, "application/json")
	}

	if result.Depth != 4 {
		t.Fatalf("unexpected depth: got %d want 4", result.Depth)
	}

	if result.FieldCount != 5 {
		t.Fatalf("unexpected field count: got %d want 5", result.FieldCount)
	}

	if result.ObjectCount != 4 {
		t.Fatalf("unexpected object count: got %d want 4", result.ObjectCount)
	}

	if result.ArrayCount != 1 {
		t.Fatalf("unexpected array count: got %d want 1", result.ArrayCount)
	}

	if result.MaxArrayLength != 2 {
		t.Fatalf("unexpected max array length: got %d want 2", result.MaxArrayLength)
	}

	wantFactors := []ScoreFactor{
		{Name: "depth", Value: 4},
		{Name: "fields", Value: 0},
		{Name: "arrays", Value: 2},
		{Name: "max_array_length", Value: 0},
	}
	if !slices.Equal(result.ScoreFactors, wantFactors) {
		t.Fatalf("unexpected score factors: got %+v want %+v", result.ScoreFactors, wantFactors)
	}

	if result.Score != 6 {
		t.Fatalf("unexpected score: got %d want 6", result.Score)
	}
}

func TestAnalyzeComplexityEmitsWarningWhenJSONLimitIsExceeded(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		observed:    []byte(`{"a":{"b":{"c":1}}}`),
		analyzed:    true,
	}

	cfg := DefaultConfig().Complexity
	cfg.MaxJSONDepth = 2

	var warnings []Warning
	result := analyzeComplexity(sample, cfg, &warnings)

	if result == nil {
		t.Fatal("expected complexity result")
	}

	if result.Depth != 2 {
		t.Fatalf("unexpected recorded depth after limit hit: got %d want 2", result.Depth)
	}

	if !hasWarningCode(warnings, "complexity_limit_exceeded") {
		t.Fatalf("expected complexity_limit_exceeded warning, got %+v", warnings)
	}
}

func TestAnalyzeComplexityFormStats(t *testing.T) {
	sample := bodySample{
		contentType: "application/x-www-form-urlencoded",
		observed:    []byte("a=1&a=2&b=3"),
		analyzed:    true,
	}

	var warnings []Warning
	result := analyzeComplexity(sample, DefaultConfig().Complexity, &warnings)

	if result == nil {
		t.Fatal("expected complexity result")
	}

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	if result.Depth != 1 {
		t.Fatalf("unexpected depth: got %d want 1", result.Depth)
	}

	if result.FieldCount != 3 {
		t.Fatalf("unexpected field count: got %d want 3", result.FieldCount)
	}

	if result.ObjectCount != 1 {
		t.Fatalf("unexpected object count: got %d want 1", result.ObjectCount)
	}

	if result.ArrayCount != 1 {
		t.Fatalf("unexpected repeated key count: got %d want 1", result.ArrayCount)
	}

	if result.MaxArrayLength != 2 {
		t.Fatalf("unexpected max values per key: got %d want 2", result.MaxArrayLength)
	}

	if result.Score != 3 {
		t.Fatalf("unexpected score: got %d want 3", result.Score)
	}
}

func TestAnalyzeCharsetFlagsSuspiciousPatterns(t *testing.T) {
	data := append([]byte("abc123 \u200b汉"), 0xff)
	sample := bodySample{
		contentType: "text/plain",
		sample:      data,
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:         64,
		EnableUnicodeScripts:    true,
		EnableSuspiciousPattern: true,
	})

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.TotalChars != 10 {
		t.Fatalf("unexpected total chars: got %d want 10", result.TotalChars)
	}

	if result.ASCIIAlphaRatio <= 0 {
		t.Fatalf("expected ASCIIAlphaRatio to be positive, got %f", result.ASCIIAlphaRatio)
	}

	if result.DigitRatio <= 0 {
		t.Fatalf("expected DigitRatio to be positive, got %f", result.DigitRatio)
	}

	if result.NonASCIIRatio <= 0 {
		t.Fatalf("expected NonASCIIRatio to be positive, got %f", result.NonASCIIRatio)
	}

	wantFlags := []string{
		"invalid_utf8",
		"control_chars",
		"zero_width_chars",
		"mixed_unicode_scripts",
	}
	for _, flag := range wantFlags {
		if !slices.Contains(result.SuspiciousFlags, flag) {
			t.Fatalf("missing suspicious flag %q in %+v", flag, result.SuspiciousFlags)
		}
	}
}
