package webprofiler

import (
	"slices"
	"testing"
)

func TestDefaultConfigProvidesSafeDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.EnableEntropy || !cfg.EnableFingerprint || !cfg.EnableComplexity || !cfg.EnableCharset {
		t.Fatalf("default config should enable all analyzers: %+v", cfg)
	}

	if cfg.Body.MaxReadBytes != defaultMaxReadBytes {
		t.Fatalf("unexpected MaxReadBytes: got %d want %d", cfg.Body.MaxReadBytes, defaultMaxReadBytes)
	}

	if cfg.Body.MaxDecompressedBytes != defaultMaxReadBytes {
		t.Fatalf("unexpected MaxDecompressedBytes: got %d want %d", cfg.Body.MaxDecompressedBytes, defaultMaxReadBytes)
	}

	if cfg.Body.StreamReadChunkSize != defaultReadChunkSize {
		t.Fatalf("unexpected StreamReadChunkSize: got %d want %d", cfg.Body.StreamReadChunkSize, defaultReadChunkSize)
	}

	if cfg.Body.SampleBytes != defaultSampleBytes {
		t.Fatalf("unexpected SampleBytes: got %d want %d", cfg.Body.SampleBytes, defaultSampleBytes)
	}

	if cfg.Body.SampleStrategy != SampleStrategyHead {
		t.Fatalf("unexpected SampleStrategy: got %q want %q", cfg.Body.SampleStrategy, SampleStrategyHead)
	}

	if !slices.Equal(cfg.Body.AnalyzeMethods, defaultAnalyzeMethods) {
		t.Fatalf("unexpected AnalyzeMethods: got %v want %v", cfg.Body.AnalyzeMethods, defaultAnalyzeMethods)
	}

	if !slices.Equal(cfg.Body.AnalyzeContentTypes, defaultAnalyzeContentTypes) {
		t.Fatalf("unexpected AnalyzeContentTypes: got %v want %v", cfg.Body.AnalyzeContentTypes, defaultAnalyzeContentTypes)
	}

	if cfg.Fingerprint.IncludeIP {
		t.Fatal("default config should not include client IP in the fingerprint")
	}

	if cfg.Fingerprint.TrustProxy {
		t.Fatal("default config should not trust proxy headers")
	}

	if !cfg.Fingerprint.IncludeTLS {
		t.Fatal("default config should include TLS data when available")
	}

	if !slices.Equal(cfg.Fingerprint.Headers, defaultFingerprintHeaders) {
		t.Fatalf("unexpected fingerprint headers: got %v want %v", cfg.Fingerprint.Headers, defaultFingerprintHeaders)
	}

	if !slices.Equal(cfg.Fingerprint.ProxyHeaders, defaultProxyHeaders) {
		t.Fatalf("unexpected proxy headers: got %v want %v", cfg.Fingerprint.ProxyHeaders, defaultProxyHeaders)
	}

	if cfg.Fingerprint.HashAlgorithm != defaultHashAlgorithm {
		t.Fatalf("unexpected hash algorithm: got %q want %q", cfg.Fingerprint.HashAlgorithm, defaultHashAlgorithm)
	}

	if cfg.Fingerprint.HashVersion != defaultHashVersion {
		t.Fatalf("unexpected hash version: got %q want %q", cfg.Fingerprint.HashVersion, defaultHashVersion)
	}

	if !cfg.Fingerprint.ExposeFields {
		t.Fatal("default config should expose normalized fingerprint fields")
	}

	if len(cfg.Fingerprint.TrustedProxyCIDRs) != 0 {
		t.Fatalf("default config should not force trusted proxy CIDRs, got %v", cfg.Fingerprint.TrustedProxyCIDRs)
	}

	if cfg.Complexity.MaxJSONDepth != defaultMaxJSONDepth {
		t.Fatalf("unexpected MaxJSONDepth: got %d want %d", cfg.Complexity.MaxJSONDepth, defaultMaxJSONDepth)
	}

	if cfg.Complexity.MaxFields != defaultMaxFields {
		t.Fatalf("unexpected MaxFields: got %d want %d", cfg.Complexity.MaxFields, defaultMaxFields)
	}

	if !cfg.Complexity.EnableFormAnalysis {
		t.Fatal("default config should enable form complexity analysis")
	}

	if cfg.Charset.MaxAnalyzeBytes != defaultCharsetAnalyzeBytes {
		t.Fatalf("unexpected MaxAnalyzeBytes: got %d want %d", cfg.Charset.MaxAnalyzeBytes, defaultCharsetAnalyzeBytes)
	}

	if !cfg.Charset.EnableSuspiciousPattern {
		t.Fatal("default config should enable suspicious charset pattern detection")
	}

	if !cfg.Charset.EnableConfusableDetection {
		t.Fatal("default config should enable confusable character detection")
	}

	if !cfg.Charset.EnableFormatSpecificMetrics {
		t.Fatal("default config should enable format-specific charset metrics")
	}
}

func TestDefaultConfigReturnsIndependentSlices(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := DefaultConfig()

	cfg1.Body.AnalyzeMethods[0] = "DELETE"
	cfg1.Body.AnalyzeContentTypes[0] = "application/octet-stream"
	cfg1.Fingerprint.Headers[0] = "authorization"
	cfg1.Fingerprint.ProxyHeaders[0] = "forwarded"
	cfg1.Complexity.SupportedContentTypes[0] = "multipart/form-data"

	if cfg2.Body.AnalyzeMethods[0] != defaultAnalyzeMethods[0] {
		t.Fatalf("AnalyzeMethods slices should not be shared: got %q want %q", cfg2.Body.AnalyzeMethods[0], defaultAnalyzeMethods[0])
	}

	if cfg2.Body.AnalyzeContentTypes[0] != defaultAnalyzeContentTypes[0] {
		t.Fatalf("AnalyzeContentTypes slices should not be shared: got %q want %q", cfg2.Body.AnalyzeContentTypes[0], defaultAnalyzeContentTypes[0])
	}

	if cfg2.Fingerprint.Headers[0] != defaultFingerprintHeaders[0] {
		t.Fatalf("Fingerprint.Headers slices should not be shared: got %q want %q", cfg2.Fingerprint.Headers[0], defaultFingerprintHeaders[0])
	}

	if cfg2.Fingerprint.ProxyHeaders[0] != defaultProxyHeaders[0] {
		t.Fatalf("Fingerprint.ProxyHeaders slices should not be shared: got %q want %q", cfg2.Fingerprint.ProxyHeaders[0], defaultProxyHeaders[0])
	}

	if cfg2.Complexity.SupportedContentTypes[0] != defaultComplexityContentTypes[0] {
		t.Fatalf("Complexity.SupportedContentTypes slices should not be shared: got %q want %q", cfg2.Complexity.SupportedContentTypes[0], defaultComplexityContentTypes[0])
	}
}

func TestNormalizeConfigSanitizesInvalidValues(t *testing.T) {
	cfg := normalizeConfig(Config{
		Body: BodyConfig{
			MaxReadBytes:         4,
			MaxDecompressedBytes: 0,
			StreamReadChunkSize:  0,
			SampleBytes:          99,
			SampleStrategy:       SampleStrategy("weird"),
			AnalyzeMethods:       []string{" post ", "POST", "", " put "},
			AnalyzeContentTypes:  []string{" application/json ", "Application/JSON", "", " text/* "},
		},
		Fingerprint: FingerprintConfig{
			Headers:           []string{" User-Agent ", "user-agent", " Accept-Language "},
			ProxyHeaders:      []string{" X-Forwarded-For ", "x-forwarded-for"},
			TrustedProxyCIDRs: []string{" 10.0.0.0/8 ", "10.0.0.0/8"},
			HashAlgorithm:     " ",
			HashVersion:       " ",
		},
		Complexity: ComplexityConfig{
			MaxJSONDepth:          0,
			MaxFields:             -1,
			SupportedContentTypes: []string{" Application/JSON ", "application/json", " multipart/form-data "},
		},
		Charset: CharsetConfig{
			MaxAnalyzeBytes: 0,
		},
	})

	if cfg.Body.MaxReadBytes != 4 {
		t.Fatalf("unexpected MaxReadBytes: got %d want 4", cfg.Body.MaxReadBytes)
	}

	if cfg.Body.SampleBytes != 4 {
		t.Fatalf("SampleBytes should be clamped to MaxReadBytes: got %d want 4", cfg.Body.SampleBytes)
	}

	if cfg.Body.MaxDecompressedBytes != 4 {
		t.Fatalf("MaxDecompressedBytes should default to MaxReadBytes: got %d want 4", cfg.Body.MaxDecompressedBytes)
	}

	if cfg.Body.StreamReadChunkSize != defaultReadChunkSize {
		t.Fatalf("unexpected StreamReadChunkSize fallback: got %d want %d", cfg.Body.StreamReadChunkSize, defaultReadChunkSize)
	}

	if cfg.Body.SampleStrategy != SampleStrategyHead {
		t.Fatalf("unsupported sample strategy should fall back to %q, got %q", SampleStrategyHead, cfg.Body.SampleStrategy)
	}

	if !slices.Equal(cfg.Body.AnalyzeMethods, []string{"POST", "PUT"}) {
		t.Fatalf("unexpected AnalyzeMethods normalization: got %v", cfg.Body.AnalyzeMethods)
	}

	if !slices.Equal(cfg.Body.AnalyzeContentTypes, []string{"application/json", "text/*"}) {
		t.Fatalf("unexpected AnalyzeContentTypes normalization: got %v", cfg.Body.AnalyzeContentTypes)
	}

	if !slices.Equal(cfg.Fingerprint.Headers, []string{"user-agent", "accept-language"}) {
		t.Fatalf("unexpected fingerprint header normalization: got %v", cfg.Fingerprint.Headers)
	}

	if !slices.Equal(cfg.Fingerprint.ProxyHeaders, []string{"x-forwarded-for"}) {
		t.Fatalf("unexpected proxy header normalization: got %v", cfg.Fingerprint.ProxyHeaders)
	}

	if !slices.Equal(cfg.Fingerprint.TrustedProxyCIDRs, []string{"10.0.0.0/8"}) {
		t.Fatalf("unexpected trusted proxy CIDR normalization: got %v", cfg.Fingerprint.TrustedProxyCIDRs)
	}

	if cfg.Fingerprint.HashAlgorithm != defaultHashAlgorithm {
		t.Fatalf("unexpected hash algorithm fallback: got %q want %q", cfg.Fingerprint.HashAlgorithm, defaultHashAlgorithm)
	}

	if cfg.Fingerprint.HashVersion != defaultHashVersion {
		t.Fatalf("unexpected hash version fallback: got %q want %q", cfg.Fingerprint.HashVersion, defaultHashVersion)
	}

	if cfg.Complexity.MaxJSONDepth != defaultMaxJSONDepth {
		t.Fatalf("unexpected MaxJSONDepth fallback: got %d want %d", cfg.Complexity.MaxJSONDepth, defaultMaxJSONDepth)
	}

	if cfg.Complexity.MaxFields != defaultMaxFields {
		t.Fatalf("unexpected MaxFields fallback: got %d want %d", cfg.Complexity.MaxFields, defaultMaxFields)
	}

	if !slices.Equal(cfg.Complexity.SupportedContentTypes, []string{"application/json", "multipart/form-data"}) {
		t.Fatalf("unexpected complexity content-type normalization: got %v", cfg.Complexity.SupportedContentTypes)
	}

	if cfg.Charset.MaxAnalyzeBytes != defaultCharsetAnalyzeBytes {
		t.Fatalf("unexpected MaxAnalyzeBytes fallback: got %d want %d", cfg.Charset.MaxAnalyzeBytes, defaultCharsetAnalyzeBytes)
	}
}

func TestNormalizeConfigKeepsSupportedSampleStrategies(t *testing.T) {
	for _, strategy := range []SampleStrategy{SampleStrategyHead, SampleStrategyTail, SampleStrategyHeadTail} {
		cfg := normalizeConfig(Config{
			Body: BodyConfig{
				MaxReadBytes:   16,
				SampleBytes:    8,
				SampleStrategy: strategy,
			},
		})

		if cfg.Body.SampleStrategy != strategy {
			t.Fatalf("supported sample strategy should be preserved: got %q want %q", cfg.Body.SampleStrategy, strategy)
		}
	}
}
