package webprofiler

import "strings"

const (
	defaultMaxReadBytes        int64 = 1 << 20
	defaultSampleBytes               = 32 << 10
	defaultCharsetAnalyzeBytes       = 16 << 10
	defaultMaxJSONDepth              = 32
	defaultMaxFields                 = 10_000
	defaultHashAlgorithm             = "sha256"
	defaultHashVersion               = "v1"
)

var (
	defaultAnalyzeMethods = []string{
		"POST",
		"PUT",
		"PATCH",
	}

	defaultAnalyzeContentTypes = []string{
		"application/json",
		"application/*+json",
		"application/x-www-form-urlencoded",
		"text/*",
		"application/xml",
		"application/*+xml",
	}

	defaultFingerprintHeaders = []string{
		"host",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
	}

	defaultProxyHeaders = []string{
		"x-forwarded-for",
		"x-real-ip",
	}

	defaultComplexityContentTypes = []string{
		"application/json",
		"application/*+json",
		"application/x-www-form-urlencoded",
	}
)

type SampleStrategy string

const (
	SampleStrategyHead SampleStrategy = "head"
)

type Config struct {
	EnableEntropy     bool
	EnableFingerprint bool
	EnableComplexity  bool
	EnableCharset     bool

	Body        BodyConfig
	Fingerprint FingerprintConfig
	Complexity  ComplexityConfig
	Charset     CharsetConfig
}

type BodyConfig struct {
	MaxReadBytes        int64
	SampleBytes         int
	SampleStrategy      SampleStrategy
	AnalyzeMethods      []string
	AnalyzeContentTypes []string
}

type FingerprintConfig struct {
	Headers       []string
	IncludeIP     bool
	IncludeTLS    bool
	TrustProxy    bool
	ProxyHeaders  []string
	HashAlgorithm string
	HashVersion   string
}

type ComplexityConfig struct {
	MaxJSONDepth          int
	MaxFields             int
	SupportedContentTypes []string
	EnableFormAnalysis    bool
	EnableMultipartMeta   bool
}

type CharsetConfig struct {
	MaxAnalyzeBytes         int
	EnableUnicodeScripts    bool
	EnableSuspiciousPattern bool
}

func DefaultConfig() Config {
	return normalizeConfig(Config{
		EnableEntropy:     true,
		EnableFingerprint: true,
		EnableComplexity:  true,
		EnableCharset:     true,
		Body: BodyConfig{
			MaxReadBytes:        defaultMaxReadBytes,
			SampleBytes:         defaultSampleBytes,
			SampleStrategy:      SampleStrategyHead,
			AnalyzeMethods:      append([]string(nil), defaultAnalyzeMethods...),
			AnalyzeContentTypes: append([]string(nil), defaultAnalyzeContentTypes...),
		},
		Fingerprint: FingerprintConfig{
			Headers:       append([]string(nil), defaultFingerprintHeaders...),
			IncludeTLS:    true,
			ProxyHeaders:  append([]string(nil), defaultProxyHeaders...),
			HashAlgorithm: defaultHashAlgorithm,
			HashVersion:   defaultHashVersion,
		},
		Complexity: ComplexityConfig{
			MaxJSONDepth:          defaultMaxJSONDepth,
			MaxFields:             defaultMaxFields,
			SupportedContentTypes: append([]string(nil), defaultComplexityContentTypes...),
			EnableFormAnalysis:    true,
		},
		Charset: CharsetConfig{
			MaxAnalyzeBytes:         defaultCharsetAnalyzeBytes,
			EnableSuspiciousPattern: true,
		},
	})
}

func normalizeConfig(cfg Config) Config {
	if cfg.Body.MaxReadBytes <= 0 {
		cfg.Body.MaxReadBytes = defaultMaxReadBytes
	}

	if cfg.Body.SampleBytes <= 0 {
		cfg.Body.SampleBytes = defaultSampleBytes
	}

	maxReadBytes := clampInt64ToInt(cfg.Body.MaxReadBytes)
	if maxReadBytes > 0 && cfg.Body.SampleBytes > maxReadBytes {
		cfg.Body.SampleBytes = maxReadBytes
	}

	if cfg.Body.SampleStrategy != SampleStrategyHead {
		cfg.Body.SampleStrategy = SampleStrategyHead
	}

	if len(cfg.Body.AnalyzeMethods) == 0 {
		cfg.Body.AnalyzeMethods = append([]string(nil), defaultAnalyzeMethods...)
	} else {
		cfg.Body.AnalyzeMethods = normalizeMethods(cfg.Body.AnalyzeMethods)
	}

	if len(cfg.Body.AnalyzeContentTypes) == 0 {
		cfg.Body.AnalyzeContentTypes = append([]string(nil), defaultAnalyzeContentTypes...)
	} else {
		cfg.Body.AnalyzeContentTypes = normalizeValues(cfg.Body.AnalyzeContentTypes)
	}

	if len(cfg.Fingerprint.Headers) == 0 {
		cfg.Fingerprint.Headers = append([]string(nil), defaultFingerprintHeaders...)
	} else {
		cfg.Fingerprint.Headers = normalizeValues(cfg.Fingerprint.Headers)
	}

	if len(cfg.Fingerprint.ProxyHeaders) == 0 {
		cfg.Fingerprint.ProxyHeaders = append([]string(nil), defaultProxyHeaders...)
	} else {
		cfg.Fingerprint.ProxyHeaders = normalizeValues(cfg.Fingerprint.ProxyHeaders)
	}

	cfg.Fingerprint.HashAlgorithm = strings.ToLower(strings.TrimSpace(cfg.Fingerprint.HashAlgorithm))
	if cfg.Fingerprint.HashAlgorithm == "" {
		cfg.Fingerprint.HashAlgorithm = defaultHashAlgorithm
	}

	cfg.Fingerprint.HashVersion = strings.TrimSpace(cfg.Fingerprint.HashVersion)
	if cfg.Fingerprint.HashVersion == "" {
		cfg.Fingerprint.HashVersion = defaultHashVersion
	}

	if cfg.Complexity.MaxJSONDepth <= 0 {
		cfg.Complexity.MaxJSONDepth = defaultMaxJSONDepth
	}

	if cfg.Complexity.MaxFields <= 0 {
		cfg.Complexity.MaxFields = defaultMaxFields
	}

	if len(cfg.Complexity.SupportedContentTypes) == 0 {
		cfg.Complexity.SupportedContentTypes = append([]string(nil), defaultComplexityContentTypes...)
	} else {
		cfg.Complexity.SupportedContentTypes = normalizeValues(cfg.Complexity.SupportedContentTypes)
	}

	if cfg.Charset.MaxAnalyzeBytes <= 0 {
		cfg.Charset.MaxAnalyzeBytes = defaultCharsetAnalyzeBytes
	}

	return cfg
}

func normalizeMethods(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	if len(normalized) == 0 {
		return append([]string(nil), defaultAnalyzeMethods...)
	}

	return normalized
}

func normalizeValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	return normalized
}

func clampInt64ToInt(value int64) int {
	if value <= 0 {
		return 0
	}
	if value > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(value)
}
