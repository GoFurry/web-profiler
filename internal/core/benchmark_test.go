package core

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

var (
	benchmarkComplexitySink  *ComplexityResult
	benchmarkCharsetSink     *CharsetResult
	benchmarkFingerprintSink *FingerprintResult
	benchmarkProfileSink     *Profile
	benchmarkBodySampleSink  bodySample
)

func BenchmarkAnalyzeComplexityJSONLarge(b *testing.B) {
	payload := buildBenchmarkJSONPayload(240, 6, 96)
	sample := bodySample{
		contentType: "application/json",
		observed:    payload,
		sample:      payload,
		analyzed:    true,
	}
	cfg := DefaultConfig().Complexity

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkComplexitySink = analyzeComplexity(sample, cfg, nil)
	}
}

func BenchmarkAnalyzeComplexityXMLLarge(b *testing.B) {
	payload := buildBenchmarkXMLPayload(260, 4, 80)
	sample := bodySample{
		contentType: "application/xml",
		observed:    payload,
		sample:      payload,
		analyzed:    true,
	}
	cfg := DefaultConfig().Complexity

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkComplexitySink = analyzeComplexity(sample, cfg, nil)
	}
}

func BenchmarkAnalyzeComplexityFormLarge(b *testing.B) {
	payload := buildBenchmarkFormPayload(320, 3, 64)
	sample := bodySample{
		contentType: "application/x-www-form-urlencoded",
		observed:    payload,
		sample:      payload,
		analyzed:    true,
	}
	cfg := DefaultConfig().Complexity

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkComplexitySink = analyzeComplexity(sample, cfg, nil)
	}
}

func BenchmarkAnalyzeComplexityMultipartMetaLarge(b *testing.B) {
	rawType, payload := buildBenchmarkMultipartPayload(40, 12, 128, 2048)
	sample := bodySample{
		contentType: "multipart/form-data",
		rawType:     rawType,
		observed:    payload,
		sample:      payload,
		analyzed:    true,
	}
	cfg := DefaultConfig().Complexity
	cfg.EnableMultipartMeta = true
	cfg.SupportedContentTypes = append(cfg.SupportedContentTypes, "multipart/form-data")

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkComplexitySink = analyzeComplexity(sample, cfg, nil)
	}
}

func BenchmarkAnalyzeCharsetJSONLarge(b *testing.B) {
	payload := buildBenchmarkJSONPayload(180, 5, 80)
	sample := bodySample{
		contentType: "application/json",
		observed:    payload,
		sample:      payload,
		analyzed:    true,
	}
	cfg := DefaultConfig().Charset
	cfg.MaxAnalyzeBytes = len(payload)
	cfg.EnableUnicodeScripts = true

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCharsetSink = analyzeCharset(sample, cfg, nil)
	}
}

func BenchmarkAnalyzeFingerprintProxyHeaders(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/checkout", nil)
	req.Host = "API.Example.com:443"
	req.RemoteAddr = "10.0.0.9:8443"
	req.Header.Set("User-Agent", "BenchmarkClient/1.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US, zh-CN")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Forwarded", `for=203.0.113.10;proto=https, for=198.51.100.5`)
	cfg := DefaultConfig().Fingerprint
	cfg.IncludeIP = true
	cfg.IncludeTLS = false
	cfg.TrustProxy = true
	cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkFingerprintSink = analyzeFingerprint(req, cfg, nil)
	}
}

func BenchmarkCaptureBodyCompressedJSON(b *testing.B) {
	payload := buildBenchmarkJSONPayload(220, 6, 96)
	cfg := DefaultConfig().Body
	cfg.EnableCompressedAnalysis = true
	cfg.MaxReadBytes = int64(len(payload) * 4)
	cfg.MaxDecompressedBytes = int64(len(payload) * 2)
	cfg.SampleBytes = 32 << 10

	b.Run("gzip", func(b *testing.B) {
		encoded := mustGzipBytes(payload)
		benchmarkCaptureBodyCompressed(b, payload, encoded, "gzip", cfg)
	})

	b.Run("deflate", func(b *testing.B) {
		encoded := mustDeflateBytes(payload)
		benchmarkCaptureBodyCompressed(b, payload, encoded, "deflate", cfg)
	})

	b.Run("raw_deflate", func(b *testing.B) {
		encoded := mustRawDeflateBytes(payload)
		benchmarkCaptureBodyCompressed(b, payload, encoded, "deflate", cfg)
	})

	b.Run("gzip_deflate_chain", func(b *testing.B) {
		encoded := mustDeflateBytes(mustGzipBytes(payload))
		benchmarkCaptureBodyCompressed(b, payload, encoded, "gzip, deflate", cfg)
	})
}

func BenchmarkAnalyzeRequestLargeJSON(b *testing.B) {
	payload := buildBenchmarkJSONPayload(220, 6, 96)
	cfg := DefaultConfig()
	cfg.Body.MaxReadBytes = int64(len(payload) * 2)
	cfg.Body.MaxDecompressedBytes = cfg.Body.MaxReadBytes
	cfg.Body.SampleBytes = len(payload)
	cfg.Charset.MaxAnalyzeBytes = len(payload)
	cfg.Fingerprint.IncludeIP = true
	cfg.Fingerprint.TrustProxy = true
	cfg.Fingerprint.TrustedProxyCIDRs = []string{"10.0.0.0/8"}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/orders", io.NopCloser(bytes.NewReader(payload)))
		req.Host = "api.example.com"
		req.RemoteAddr = "10.0.0.8:9443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Forwarded", "for=203.0.113.8;proto=https")
		req.Header.Set("User-Agent", "BenchmarkClient/1.0")
		benchmarkProfileSink = analyzeRequest(req, cfg)
	}
}

func BenchmarkAnalyzeRequestCompressedJSON(b *testing.B) {
	payload := buildBenchmarkJSONPayload(220, 6, 96)
	encoded := mustGzipBytes(payload)
	cfg := DefaultConfig()
	cfg.Body.EnableCompressedAnalysis = true
	cfg.Body.MaxReadBytes = int64(len(encoded) * 2)
	cfg.Body.MaxDecompressedBytes = int64(len(payload) * 2)
	cfg.Body.SampleBytes = len(payload)
	cfg.Charset.MaxAnalyzeBytes = len(payload)
	cfg.Fingerprint.IncludeIP = true
	cfg.Fingerprint.TrustProxy = true
	cfg.Fingerprint.TrustedProxyCIDRs = []string{"10.0.0.0/8"}

	b.ReportAllocs()
	b.SetBytes(int64(len(encoded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/orders", io.NopCloser(bytes.NewReader(encoded)))
		req.Host = "api.example.com"
		req.RemoteAddr = "10.0.0.8:9443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Forwarded", "for=203.0.113.8;proto=https")
		req.Header.Set("User-Agent", "BenchmarkClient/1.0")
		benchmarkProfileSink = analyzeRequest(req, cfg)
	}
}

func benchmarkCaptureBodyCompressed(b *testing.B, decodedPayload, encodedPayload []byte, encoding string, cfg BodyConfig) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", io.NopCloser(bytes.NewReader(encodedPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", encoding)
	initialWarnings := make([]Warning, 0, 4)
	initialSample := captureBody(req, cfg, &initialWarnings)
	if len(initialSample.observed) == 0 || (encoding != "" && !bytes.Equal(initialSample.observed, decodedPayload)) {
		b.Fatalf("unexpected captured body state for encoding %q", encoding)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(encodedPayload)))
	warnings := make([]Warning, 0, 4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", io.NopCloser(bytes.NewReader(encodedPayload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", encoding)
		warnings = warnings[:0]
		benchmarkBodySampleSink = captureBody(req, cfg, &warnings)
	}
}

func buildBenchmarkJSONPayload(recordCount, tagCount, textLen int) []byte {
	var builder strings.Builder
	builder.Grow(recordCount * (textLen + 180))
	builder.WriteString(`{"records":[`)
	for i := 0; i < recordCount; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`{"id":`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`,"path":"/api/v1/resource/`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`","name":"`)
		builder.WriteString(strings.Repeat("alpha", textLen/5))
		builder.WriteString(`","active":true,"tags":[`)
		for tag := 0; tag < tagCount; tag++ {
			if tag > 0 {
				builder.WriteByte(',')
			}
			builder.WriteString(`"tag-`)
			builder.WriteString(strconv.Itoa(tag))
			builder.WriteByte('"')
		}
		builder.WriteString(`],"meta":{"lang":"zh-CN","region":"apac","owner":"team-`)
		builder.WriteString(strconv.Itoa(i % 12))
		builder.WriteString(`","note":"`)
		builder.WriteString(strings.Repeat("混合GreekΑΒ", maxInt(textLen/16, 1)))
		builder.WriteString(`"}}`)
	}
	builder.WriteString(`],"summary":{"service":"checkout","env":"prod","message":"`)
	builder.WriteString(strings.Repeat("bench", maxInt(textLen/8, 1)))
	builder.WriteString(`"}}`)
	return []byte(builder.String())
}

func buildBenchmarkXMLPayload(elementCount, attrCount, textLen int) []byte {
	var builder strings.Builder
	builder.Grow(elementCount * (textLen + 120))
	builder.WriteString(`<root service="checkout" env="prod">`)
	for i := 0; i < elementCount; i++ {
		builder.WriteString(`<item id="`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`" shard="`)
		builder.WriteString(strconv.Itoa(i % 16))
		builder.WriteString(`"`)
		for attr := 0; attr < attrCount; attr++ {
			builder.WriteByte(' ')
			builder.WriteString(`attr`)
			builder.WriteString(strconv.Itoa(attr))
			builder.WriteString(`="`)
			builder.WriteString(strings.Repeat("v", maxInt(textLen/16, 1)))
			builder.WriteByte('"')
		}
		builder.WriteString(`><name>item-`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`</name><note>`)
		builder.WriteString(strings.Repeat("payload-", maxInt(textLen/8, 1)))
		builder.WriteString(`</note></item>`)
	}
	builder.WriteString(`</root>`)
	return []byte(builder.String())
}

func buildBenchmarkFormPayload(fieldCount, valuesPerField, valueLen int) []byte {
	var builder strings.Builder
	builder.Grow(fieldCount * valuesPerField * (valueLen + 24))
	for field := 0; field < fieldCount; field++ {
		for valueIdx := 0; valueIdx < valuesPerField; valueIdx++ {
			if builder.Len() > 0 {
				builder.WriteByte('&')
			}
			builder.WriteString(`field`)
			builder.WriteString(strconv.Itoa(field))
			builder.WriteByte('=')
			builder.WriteString(strings.Repeat("x", valueLen))
			builder.WriteString(strconv.Itoa(valueIdx))
		}
	}
	return []byte(builder.String())
}

func buildBenchmarkMultipartPayload(fieldCount, fileCount, valueLen, fileSize int) (string, []byte) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	for field := 0; field < fieldCount; field++ {
		_ = writer.WriteField("field"+strconv.Itoa(field%10), strings.Repeat("value-", maxInt(valueLen/6, 1)))
	}

	fileBody := bytes.Repeat([]byte("a"), fileSize)
	for file := 0; file < fileCount; file++ {
		part, err := writer.CreateFormFile("upload"+strconv.Itoa(file%4), "file-"+strconv.Itoa(file)+".json")
		if err != nil {
			panic(err)
		}
		if _, err := part.Write(fileBody); err != nil {
			panic(err)
		}
	}

	if err := writer.Close(); err != nil {
		panic(err)
	}

	return writer.FormDataContentType(), buffer.Bytes()
}

func mustGzipBytes(data []byte) []byte {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func mustDeflateBytes(data []byte) []byte {
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func mustRawDeflateBytes(data []byte) []byte {
	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		panic(err)
	}
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
