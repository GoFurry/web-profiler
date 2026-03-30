package webprofiler

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"mime/multipart"
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
		ExposeFields:  true,
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

	if result.Hash != hashFields(result.Fields, "v2", "sha256") {
		t.Fatalf("fingerprint hash should be reproducible, got %q", result.Hash)
	}

	if !slices.Equal(result.SourceFlags, []string{"headers", "tls", "ip"}) {
		t.Fatalf("unexpected fingerprint source flags: got %v", result.SourceFlags)
	}

	weakFields := map[string]string{
		"accept-language": "en-us, zh-cn",
		"host":            "example.com:443",
		"tls.alpn":        "h2",
		"tls.sni":         "api.example.com",
		"tls.version":     "tls1.3",
		"user-agent":      "fancy client/1.0",
	}
	if result.WeakHash != hashFields(weakFields, "v2", "sha256") {
		t.Fatalf("unexpected weak fingerprint hash: got %q", result.WeakHash)
	}

	if result.StrongHash != result.Hash {
		t.Fatalf("strong hash should mirror legacy hash field: got strong=%q hash=%q", result.StrongHash, result.Hash)
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

func TestAnalyzeFingerprintSupportsHashOnlyMode(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ping", nil)
	req.Header.Set("User-Agent", "curl/8.0")

	result := analyzeFingerprint(req, FingerprintConfig{
		Headers:       []string{"host", "user-agent"},
		ExposeFields:  false,
		HashAlgorithm: "sha256",
		HashVersion:   "v1",
	}, nil)

	if result == nil {
		t.Fatal("expected fingerprint result")
	}

	if result.Fields != nil {
		t.Fatalf("hash-only mode should omit raw fields, got %+v", result.Fields)
	}

	if result.Hash == "" || result.WeakHash == "" || result.StrongHash == "" {
		t.Fatalf("hash-only mode should still produce hashes: %+v", result)
	}
}

func TestAnalyzeFingerprintSupportsAlternateHashAlgorithms(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ping", nil)

	result := analyzeFingerprint(req, FingerprintConfig{
		Headers:       []string{"host"},
		ExposeFields:  true,
		HashAlgorithm: "sha512",
		HashVersion:   "v3",
	}, nil)

	if result == nil {
		t.Fatal("expected fingerprint result")
	}

	if result.HashAlgorithm != "sha512" {
		t.Fatalf("unexpected hash algorithm: got %q want %q", result.HashAlgorithm, "sha512")
	}

	if result.Hash != hashFields(result.Fields, "v3", "sha512") {
		t.Fatalf("unexpected sha512 fingerprint hash: got %q", result.Hash)
	}
}

func TestClientIPHonorsTrustedProxyCIDRs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ping", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.10")
	req.RemoteAddr = "198.51.100.20:8080"

	cfg := FingerprintConfig{
		TrustProxy:        true,
		ProxyHeaders:      []string{"x-forwarded-for"},
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	}

	if got := clientIP(req, cfg); got != "198.51.100.20" {
		t.Fatalf("unexpected client ip for untrusted proxy: got %q want %q", got, "198.51.100.20")
	}

	req.RemoteAddr = "10.1.2.3:8080"
	if got := clientIP(req, cfg); got != "203.0.113.9" {
		t.Fatalf("unexpected client ip for trusted proxy: got %q want %q", got, "203.0.113.9")
	}
}

func TestAnalyzeEntropyIncludesNormalizedAndCompressionSignals(t *testing.T) {
	sample := bodySample{
		sample:   []byte("aaaaabbbbbccccc"),
		observed: []byte("aaaaabbbbbccccc"),
		analyzed: true,
	}

	result := analyzeEntropy(sample, BodyConfig{SampleStrategy: SampleStrategyHead})
	if result == nil {
		t.Fatal("expected entropy result")
	}

	if result.UniqueByteCount != 3 {
		t.Fatalf("unexpected unique byte count: got %d want 3", result.UniqueByteCount)
	}

	if result.NormalizedValue <= 0 || result.NormalizedValue > 1 {
		t.Fatalf("normalized entropy should be in (0,1], got %f", result.NormalizedValue)
	}

	if result.RepetitionRatio <= 0 {
		t.Fatalf("expected repetition ratio to be positive, got %f", result.RepetitionRatio)
	}

	if result.CompressionRatio <= 0 {
		t.Fatalf("expected compression ratio to be positive, got %f", result.CompressionRatio)
	}

	if result.ApproxCompressibility < 0 {
		t.Fatalf("expected non-negative compressibility, got %f", result.ApproxCompressibility)
	}
}

func TestAnalyzeComplexityJSONStats(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		observed:    []byte(`{"a":[{"b":"text"},{"c":null}],"d":{"e":3}}`),
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

	if result.ScalarCount != 3 {
		t.Fatalf("unexpected scalar count: got %d want 3", result.ScalarCount)
	}

	if result.NullCount != 1 {
		t.Fatalf("unexpected null count: got %d want 1", result.NullCount)
	}

	if result.StringCount != 1 {
		t.Fatalf("unexpected string count: got %d want 1", result.StringCount)
	}

	if result.UniqueKeyCount != 5 {
		t.Fatalf("unexpected unique key count: got %d want 5", result.UniqueKeyCount)
	}

	if result.MaxArrayLength != 2 {
		t.Fatalf("unexpected max array length: got %d want 2", result.MaxArrayLength)
	}

	if result.MaxObjectFields != 2 {
		t.Fatalf("unexpected max object fields: got %d want 2", result.MaxObjectFields)
	}

	if result.MaxKeyLength != 1 {
		t.Fatalf("unexpected max key length: got %d want 1", result.MaxKeyLength)
	}

	if result.MaxStringLength != 4 {
		t.Fatalf("unexpected max string length: got %d want 4", result.MaxStringLength)
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

func TestAnalyzeComplexityCountsGloballyUniqueJSONKeys(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		observed:    []byte(`{"a":1,"nested":{"a":2,"b":3},"items":[{"b":4},{"c":5}]}`),
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

	if result.UniqueKeyCount != 5 {
		t.Fatalf("unexpected globally unique key count: got %d want %d", result.UniqueKeyCount, 5)
	}
}

func TestAnalyzeComplexityRejectsTrailingJSONData(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		observed:    []byte(`{"a":1}{"b":2}`),
		analyzed:    true,
	}

	var warnings []Warning
	result := analyzeComplexity(sample, DefaultConfig().Complexity, &warnings)

	if result != nil {
		t.Fatalf("expected complexity result to be nil for trailing JSON data, got %+v", result)
	}

	if !hasWarningCode(warnings, "complexity_parse_failed") {
		t.Fatalf("expected complexity_parse_failed warning, got %+v", warnings)
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
		observed:    []byte("a=1&a=22&bbb=333"),
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

	if result.ScalarCount != 3 {
		t.Fatalf("unexpected scalar count: got %d want 3", result.ScalarCount)
	}

	if result.StringCount != 3 {
		t.Fatalf("unexpected string count: got %d want 3", result.StringCount)
	}

	if result.UniqueKeyCount != 2 {
		t.Fatalf("unexpected unique key count: got %d want 2", result.UniqueKeyCount)
	}

	if result.MaxArrayLength != 2 {
		t.Fatalf("unexpected max values per key: got %d want 2", result.MaxArrayLength)
	}

	if result.MaxObjectFields != 2 {
		t.Fatalf("unexpected max object fields: got %d want 2", result.MaxObjectFields)
	}

	if result.MaxKeyLength != 3 {
		t.Fatalf("unexpected max key length: got %d want 3", result.MaxKeyLength)
	}

	if result.MaxValueLength != 3 {
		t.Fatalf("unexpected max value length: got %d want 3", result.MaxValueLength)
	}

	if result.AverageKeyLength != 2 {
		t.Fatalf("unexpected average key length: got %f want 2", result.AverageKeyLength)
	}

	if result.AverageValueLength != 2 {
		t.Fatalf("unexpected average value length: got %f want 2", result.AverageValueLength)
	}

	if result.Score != 3 {
		t.Fatalf("unexpected score: got %d want 3", result.Score)
	}
}

func TestAnalyzeComplexityMultipartMetadata(t *testing.T) {
	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)

	field, err := writer.CreateFormField("note")
	if err != nil {
		t.Fatalf("CreateFormField failed: %v", err)
	}
	if _, err := field.Write([]byte("hello")); err != nil {
		t.Fatalf("field write failed: %v", err)
	}

	filePart, err := writer.CreateFormFile("upload", "avatar.png")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := filePart.Write([]byte("PNGDATA")); err != nil {
		t.Fatalf("file write failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("writer close failed: %v", err)
	}

	sample := bodySample{
		contentType: "multipart/form-data",
		rawType:     writer.FormDataContentType(),
		observed:    payload.Bytes(),
		analyzed:    true,
	}

	cfg := DefaultConfig().Complexity
	cfg.EnableMultipartMeta = true
	cfg.SupportedContentTypes = append(cfg.SupportedContentTypes, "multipart/form-data")

	var warnings []Warning
	result := analyzeComplexity(sample, cfg, &warnings)
	if result == nil {
		t.Fatal("expected multipart complexity result")
	}

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	if result.MultipartFileCount != 1 {
		t.Fatalf("unexpected multipart file count: got %d want 1", result.MultipartFileCount)
	}

	if result.MultipartFieldCount != 1 {
		t.Fatalf("unexpected multipart field count: got %d want 1", result.MultipartFieldCount)
	}

	if result.MultipartFileExtensions["png"] != 1 {
		t.Fatalf("unexpected multipart extension stats: %+v", result.MultipartFileExtensions)
	}

	if result.MultipartMaxFileNameLength != len("avatar.png") {
		t.Fatalf("unexpected multipart max file name length: got %d want %d", result.MultipartMaxFileNameLength, len("avatar.png"))
	}
}

func TestAnalyzeCharsetFlagsSuspiciousPatterns(t *testing.T) {
	data := append([]byte("abc123 \u200b\u6c49\u3042\U0001F60A"), 0xff)
	sample := bodySample{
		contentType: "text/plain",
		sample:      data,
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:         64,
		EnableUnicodeScripts:    true,
		EnableSuspiciousPattern: true,
	}, nil)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.TotalChars != 12 {
		t.Fatalf("unexpected total chars: got %d want 12", result.TotalChars)
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

	if result.EmojiRatio <= 0 {
		t.Fatalf("expected EmojiRatio to be positive, got %f", result.EmojiRatio)
	}

	if result.InvisibleCharRatio <= 0 {
		t.Fatalf("expected InvisibleCharRatio to be positive, got %f", result.InvisibleCharRatio)
	}

	if result.UnicodeScriptCounts["latin"] != 3 {
		t.Fatalf("unexpected latin script count: got %d want 3", result.UnicodeScriptCounts["latin"])
	}

	if result.UnicodeScriptCounts["han"] != 1 {
		t.Fatalf("unexpected han script count: got %d want 1", result.UnicodeScriptCounts["han"])
	}

	if result.UnicodeScriptCounts["hiragana"] != 1 {
		t.Fatalf("unexpected hiragana script count: got %d want 1", result.UnicodeScriptCounts["hiragana"])
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

func TestAnalyzeCharsetAddsConfusableAndJSONFormatMetrics(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		sample:      []byte("{\"user\":\"pаypal\",\"count\":2}"),
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:             256,
		EnableUnicodeScripts:        true,
		EnableSuspiciousPattern:     true,
		EnableConfusableDetection:   true,
		EnableFormatSpecificMetrics: true,
	}, nil)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.ConfusableCount <= 0 {
		t.Fatalf("expected confusable characters to be counted, got %d", result.ConfusableCount)
	}

	if !slices.Contains(result.SuspiciousFlags, "confusable_homoglyphs") {
		t.Fatalf("expected confusable_homoglyphs flag, got %+v", result.SuspiciousFlags)
	}

	if result.FormatMetrics == nil {
		t.Fatal("expected JSON format metrics")
	}

	if result.FormatMetrics.Format != "json" {
		t.Fatalf("unexpected format metrics type: got %q want %q", result.FormatMetrics.Format, "json")
	}

	if result.FormatMetrics.KeyCount != 2 {
		t.Fatalf("unexpected JSON key count: got %d want 2", result.FormatMetrics.KeyCount)
	}

	if result.FormatMetrics.ValueCount != 2 {
		t.Fatalf("unexpected JSON value count: got %d want 2", result.FormatMetrics.ValueCount)
	}

	if result.FormatMetrics.StringValueCount != 1 || result.FormatMetrics.NumberValueCount != 1 {
		t.Fatalf("unexpected JSON format counters: %+v", result.FormatMetrics)
	}
}

func TestAnalyzeCharsetFlagsConfusableHomoglyphsWithoutUnicodeScriptAnalysis(t *testing.T) {
	sample := bodySample{
		contentType: "text/plain",
		sample:      []byte("payp\u0430l"),
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:           256,
		EnableSuspiciousPattern:   true,
		EnableConfusableDetection: true,
	}, nil)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.ConfusableCount <= 0 {
		t.Fatalf("expected confusable characters to be counted, got %d", result.ConfusableCount)
	}

	if !slices.Contains(result.SuspiciousFlags, "confusable_homoglyphs") {
		t.Fatalf("expected confusable_homoglyphs flag, got %+v", result.SuspiciousFlags)
	}
}

func TestAnalyzeCharsetRespectsAnalyzeByteLimitForUTF8Validation(t *testing.T) {
	sample := bodySample{
		contentType: "text/plain",
		sample:      append([]byte("hello"), 0xff),
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:         5,
		EnableSuspiciousPattern: true,
	}, nil)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if slices.Contains(result.SuspiciousFlags, "invalid_utf8") {
		t.Fatalf("did not expect invalid_utf8 flag outside the analyze window, got %+v", result.SuspiciousFlags)
	}
}

func TestAnalyzeCharsetAddsFormAndXMLFormatMetrics(t *testing.T) {
	formSample := bodySample{
		contentType: "application/x-www-form-urlencoded",
		sample:      []byte("a=1&a=22&bbb=333"),
		analyzed:    true,
	}
	formResult := analyzeCharset(formSample, CharsetConfig{
		MaxAnalyzeBytes:             256,
		EnableFormatSpecificMetrics: true,
	}, nil)
	if formResult == nil || formResult.FormatMetrics == nil {
		t.Fatal("expected form format metrics")
	}
	if formResult.FormatMetrics.Format != "form" {
		t.Fatalf("unexpected form format name: got %q want %q", formResult.FormatMetrics.Format, "form")
	}
	if formResult.FormatMetrics.KeyCount != 2 || formResult.FormatMetrics.ValueCount != 3 || formResult.FormatMetrics.RepeatedKeyCount != 1 {
		t.Fatalf("unexpected form format metrics: %+v", formResult.FormatMetrics)
	}

	xmlSample := bodySample{
		contentType: "application/xml",
		sample:      []byte(`<root lang="en"><name>Alice</name></root>`),
		analyzed:    true,
	}
	xmlResult := analyzeCharset(xmlSample, CharsetConfig{
		MaxAnalyzeBytes:             256,
		EnableFormatSpecificMetrics: true,
	}, nil)
	if xmlResult == nil || xmlResult.FormatMetrics == nil {
		t.Fatal("expected xml format metrics")
	}
	if xmlResult.FormatMetrics.Format != "xml" {
		t.Fatalf("unexpected xml format name: got %q want %q", xmlResult.FormatMetrics.Format, "xml")
	}
	if xmlResult.FormatMetrics.TagCount != 2 || xmlResult.FormatMetrics.AttributeCount != 1 || xmlResult.FormatMetrics.TextNodeCount != 1 {
		t.Fatalf("unexpected xml format metrics: %+v", xmlResult.FormatMetrics)
	}
}

func TestAnalyzeCharsetTrimsIncompleteUTF8SuffixAtAnalyzeBoundary(t *testing.T) {
	sample := bodySample{
		contentType: "text/plain",
		sample:      []byte("你好"),
		analyzed:    true,
	}

	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:         5,
		EnableSuspiciousPattern: true,
	}, nil)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.TotalChars != 1 {
		t.Fatalf("expected one fully decoded rune after trimming, got %d", result.TotalChars)
	}

	if slices.Contains(result.SuspiciousFlags, "invalid_utf8") {
		t.Fatalf("did not expect invalid_utf8 for boundary-trimmed UTF-8, got %+v", result.SuspiciousFlags)
	}
}

func TestAnalyzeCharsetWarnsWhenFormatMetricsArePartial(t *testing.T) {
	sample := bodySample{
		contentType: "application/json",
		sample:      []byte(`{"user":"alice"`),
		analyzed:    true,
	}

	var warnings []Warning
	result := analyzeCharset(sample, CharsetConfig{
		MaxAnalyzeBytes:             256,
		EnableFormatSpecificMetrics: true,
	}, &warnings)

	if result == nil {
		t.Fatal("expected charset result")
	}

	if result.FormatMetrics == nil {
		t.Fatal("expected partial format metrics")
	}

	if !hasWarningCode(warnings, "charset_format_metrics_partial") {
		t.Fatalf("expected charset_format_metrics_partial warning, got %+v", warnings)
	}
}

func TestDecodeObservedBodySupportsGzip(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"msg":"hello"}`)); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	decoded, truncated, applied, err := decodeObservedBody(compressed.Bytes(), "gzip", 1024, 4)
	if err != nil {
		t.Fatalf("decodeObservedBody returned error: %v", err)
	}
	if !applied {
		t.Fatal("expected gzip decoding to be applied")
	}
	if truncated {
		t.Fatal("did not expect decoded payload to be truncated")
	}
	if string(decoded) != `{"msg":"hello"}` {
		t.Fatalf("unexpected decoded payload: got %q want %q", string(decoded), `{"msg":"hello"}`)
	}
}
