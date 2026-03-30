package policy

import "strings"

const (
	defaultMaxReadBytes        int64 = 1 << 20
	defaultSampleBytes               = 32 << 10
	defaultReadChunkSize             = 8 << 10
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
	SampleStrategyHead     SampleStrategy = "head"
	SampleStrategyTail     SampleStrategy = "tail"
	SampleStrategyHeadTail SampleStrategy = "head_tail"
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
	MaxReadBytes             int64
	MaxDecompressedBytes     int64
	StreamReadChunkSize      int
	SampleBytes              int
	SampleStrategy           SampleStrategy
	EnableCompressedAnalysis bool
	AnalyzeMethods           []string
	AnalyzeContentTypes      []string
}

type FingerprintConfig struct {
	Headers           []string
	IncludeIP         bool
	IncludeTLS        bool
	TrustProxy        bool
	ProxyHeaders      []string
	TrustedProxyCIDRs []string

	// When false, the result keeps only hashes/source metadata and omits raw normalized fields.
	ExposeFields  bool
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
	MaxAnalyzeBytes             int
	EnableUnicodeScripts        bool
	EnableSuspiciousPattern     bool
	EnableConfusableDetection   bool
	EnableFormatSpecificMetrics bool
}

func DefaultConfig() Config {
	return normalizeConfig(Config{
		EnableEntropy:     true,
		EnableFingerprint: true,
		EnableComplexity:  true,
		EnableCharset:     true,
		Body: BodyConfig{
			MaxReadBytes:         defaultMaxReadBytes,
			MaxDecompressedBytes: defaultMaxReadBytes,
			StreamReadChunkSize:  defaultReadChunkSize,
			SampleBytes:          defaultSampleBytes,
			SampleStrategy:       SampleStrategyHead,
			AnalyzeMethods:       append([]string(nil), defaultAnalyzeMethods...),
			AnalyzeContentTypes:  append([]string(nil), defaultAnalyzeContentTypes...),
		},
		Fingerprint: FingerprintConfig{
			Headers:           append([]string(nil), defaultFingerprintHeaders...),
			IncludeTLS:        true,
			ProxyHeaders:      append([]string(nil), defaultProxyHeaders...),
			ExposeFields:      true,
			HashAlgorithm:     defaultHashAlgorithm,
			HashVersion:       defaultHashVersion,
			TrustedProxyCIDRs: nil,
		},
		Complexity: ComplexityConfig{
			MaxJSONDepth:          defaultMaxJSONDepth,
			MaxFields:             defaultMaxFields,
			SupportedContentTypes: append([]string(nil), defaultComplexityContentTypes...),
			EnableFormAnalysis:    true,
		},
		Charset: CharsetConfig{
			MaxAnalyzeBytes:             defaultCharsetAnalyzeBytes,
			EnableSuspiciousPattern:     true,
			EnableConfusableDetection:   true,
			EnableFormatSpecificMetrics: true,
		},
	})
}

func NormalizeConfig(cfg Config) Config {
	return normalizeConfig(cfg)
}

func normalizeConfig(cfg Config) Config {
	if cfg.Body.MaxReadBytes <= 0 {
		cfg.Body.MaxReadBytes = defaultMaxReadBytes
	}

	if cfg.Body.SampleBytes <= 0 {
		cfg.Body.SampleBytes = defaultSampleBytes
	}

	if cfg.Body.StreamReadChunkSize <= 0 {
		cfg.Body.StreamReadChunkSize = defaultReadChunkSize
	}

	maxReadBytes := clampInt64ToInt(cfg.Body.MaxReadBytes)
	if maxReadBytes > 0 && cfg.Body.SampleBytes > maxReadBytes {
		cfg.Body.SampleBytes = maxReadBytes
	}

	if cfg.Body.MaxDecompressedBytes <= 0 {
		cfg.Body.MaxDecompressedBytes = cfg.Body.MaxReadBytes
	}

	if cfg.Body.SampleStrategy != SampleStrategyHead &&
		cfg.Body.SampleStrategy != SampleStrategyTail &&
		cfg.Body.SampleStrategy != SampleStrategyHeadTail {
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
		cfg.Body.AnalyzeContentTypes = normalizeValuesOrDefault(cfg.Body.AnalyzeContentTypes, defaultAnalyzeContentTypes)
	}

	if len(cfg.Fingerprint.Headers) == 0 {
		cfg.Fingerprint.Headers = append([]string(nil), defaultFingerprintHeaders...)
	} else {
		cfg.Fingerprint.Headers = normalizeValuesOrDefault(cfg.Fingerprint.Headers, defaultFingerprintHeaders)
	}

	if len(cfg.Fingerprint.ProxyHeaders) == 0 {
		cfg.Fingerprint.ProxyHeaders = append([]string(nil), defaultProxyHeaders...)
	} else {
		cfg.Fingerprint.ProxyHeaders = normalizeValuesOrDefault(cfg.Fingerprint.ProxyHeaders, defaultProxyHeaders)
	}

	cfg.Fingerprint.TrustedProxyCIDRs = normalizeCIDRs(cfg.Fingerprint.TrustedProxyCIDRs)

	cfg.Fingerprint.HashAlgorithm = strings.ToLower(strings.TrimSpace(cfg.Fingerprint.HashAlgorithm))
	if cfg.Fingerprint.HashAlgorithm == "" {
		cfg.Fingerprint.HashAlgorithm = defaultHashAlgorithm
	}

	if !cfg.Fingerprint.ExposeFields && len(cfg.Fingerprint.Headers) == 0 {
		cfg.Fingerprint.ExposeFields = false
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
		cfg.Complexity.SupportedContentTypes = normalizeValuesOrDefault(cfg.Complexity.SupportedContentTypes, defaultComplexityContentTypes)
	}

	if cfg.Complexity.EnableMultipartMeta {
		cfg.Body.AnalyzeContentTypes = appendUniqueValue(cfg.Body.AnalyzeContentTypes, "multipart/form-data")
		cfg.Complexity.SupportedContentTypes = appendUniqueValue(cfg.Complexity.SupportedContentTypes, "multipart/form-data")
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

func normalizeValuesOrDefault(values []string, defaults []string) []string {
	normalized := normalizeValues(values)
	if len(normalized) == 0 {
		return append([]string(nil), defaults...)
	}
	return normalized
}

func appendUniqueValue(values []string, value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func normalizeCIDRs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
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
