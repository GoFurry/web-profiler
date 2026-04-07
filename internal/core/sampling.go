package core

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"mime"
	"net/http"
	"strings"
)

type bodySample struct {
	contentType     string
	rawType         string
	contentEncoding string
	wireObserved    []byte
	observed        []byte
	sample          []byte
	sampled         bool
	truncated       bool
	analyzed        bool
	decoded         bool
}

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r replayReadCloser) Close() error {
	if r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

func (s bodySample) isDecodedForStructuredAnalysis() bool {
	return !s.hasActiveContentEncoding() || s.decoded
}

func (s bodySample) hasActiveContentEncoding() bool {
	return len(parseContentEncodings(s.contentEncoding)) > 0
}

func captureBody(r *http.Request, cfg BodyConfig, warnings *[]Warning) bodySample {
	rawType := r.Header.Get("Content-Type")
	sample := bodySample{
		contentType:     normalizedContentType(rawType),
		rawType:         rawType,
		contentEncoding: strings.TrimSpace(r.Header.Get("Content-Encoding")),
	}

	if r.Body == nil || r.Body == http.NoBody {
		appendWarning(warnings, "body_skipped_empty", "request body analysis skipped because no request body was provided")
		return sample
	}

	if !containsMethod(cfg.AnalyzeMethods, r.Method) {
		appendWarning(warnings, "body_skipped_method", "request body analysis skipped because the HTTP method is not enabled for body analysis")
		return sample
	}

	if !matchesContentType(sample.contentType, cfg.AnalyzeContentTypes) {
		appendWarning(warnings, "body_skipped_content_type", "request body analysis skipped because the content type is not enabled for body analysis")
		return sample
	}

	consumed, observed, truncated, err := readLimitedBody(r.Body, cfg.MaxReadBytes, cfg.StreamReadChunkSize)
	r.Body = replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(consumed), r.Body),
		closer: r.Body,
	}

	sample.analyzed = true
	sample.wireObserved = observed
	sample.observed = observed
	sample.truncated = truncated
	if cfg.EnableCompressedAnalysis {
		decoded, decodedTruncated, applied, decodeErr := decodeObservedBody(observed, sample.contentEncoding, cfg.MaxDecompressedBytes, cfg.StreamReadChunkSize)
		switch {
		case decodeErr != nil && applied:
			appendWarning(warnings, "body_decompression_failed", decodeErr.Error())
		case decodeErr != nil && sample.contentEncoding != "":
			appendWarning(warnings, "body_content_encoding_unsupported", decodeErr.Error())
		case applied:
			sample.observed = decoded
			sample.decoded = true
			if decodedTruncated {
				appendWarning(warnings, "body_decompressed_truncated", "decoded request body observation reached MaxDecompressedBytes and was truncated")
			}
		}
	}

	if sample.hasActiveContentEncoding() && !sample.decoded {
		appendWarning(warnings, "body_encoded_not_decoded", "request body remains content-encoded, so structured and charset analysis was skipped")
	}
	sample.sample, sample.sampled = buildSample(observed, cfg.SampleBytes, cfg.SampleStrategy)
	if sample.decoded {
		sample.sample, sample.sampled = buildSample(sample.observed, cfg.SampleBytes, cfg.SampleStrategy)
	}

	if truncated {
		appendWarning(warnings, "body_truncated", "request body observation reached MaxReadBytes and was truncated")
	}

	if err != nil {
		appendWarning(warnings, "body_read_error", err.Error())
	}

	return sample
}

func buildSample(observed []byte, sampleBytes int, strategy SampleStrategy) ([]byte, bool) {
	if sampleBytes <= 0 || len(observed) == 0 {
		return nil, false
	}

	if sampleBytes >= len(observed) {
		return append([]byte(nil), observed...), false
	}

	switch strategy {
	case SampleStrategyTail:
		start := len(observed) - sampleBytes
		return append([]byte(nil), observed[start:]...), true
	case SampleStrategyHeadTail:
		headBytes := (sampleBytes + 1) / 2
		tailBytes := sampleBytes / 2
		sample := make([]byte, 0, sampleBytes)
		sample = append(sample, observed[:headBytes]...)
		sample = append(sample, observed[len(observed)-tailBytes:]...)
		return sample, true
	case SampleStrategyHead:
		fallthrough
	default:
		return append([]byte(nil), observed[:sampleBytes]...), true
	}
}

func readLimitedBody(body io.ReadCloser, maxReadBytes int64, chunkSize int) (consumed []byte, observed []byte, truncated bool, err error) {
	if maxReadBytes <= 0 {
		return nil, nil, false, nil
	}

	consumed, truncated, err = readWithLimit(body, maxReadBytes, chunkSize)
	observed = consumed
	if truncated {
		observed = consumed[:maxReadBytes]
	}

	return consumed, observed, truncated, err
}

func readWithLimit(reader io.Reader, maxBytes int64, chunkSize int) (data []byte, truncated bool, err error) {
	if maxBytes <= 0 {
		return nil, false, nil
	}
	if chunkSize <= 0 {
		chunkSize = defaultReadChunkSize
	}

	remaining := maxBytes + 1
	var buffer bytes.Buffer
	chunk := make([]byte, chunkSize)

	for remaining > 0 {
		readSize := chunkSize
		if int64(readSize) > remaining {
			readSize = int(remaining)
		}

		n, readErr := reader.Read(chunk[:readSize])
		if n > 0 {
			_, _ = buffer.Write(chunk[:n])
			remaining -= int64(n)
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return buffer.Bytes(), int64(buffer.Len()) > maxBytes, readErr
		}
		if n == 0 {
			return buffer.Bytes(), int64(buffer.Len()) > maxBytes, io.ErrNoProgress
		}
	}

	data = buffer.Bytes()
	return data, int64(len(data)) > maxBytes, nil
}

func decodeObservedBody(data []byte, encodingHeader string, maxBytes int64, chunkSize int) (decoded []byte, truncated bool, applied bool, err error) {
	encodings := parseContentEncodings(encodingHeader)
	if len(encodings) == 0 {
		return nil, false, false, nil
	}

	current := append([]byte(nil), data...)
	for i := len(encodings) - 1; i >= 0; i-- {
		current, truncated, err = decodeContentEncodingLayer(current, encodings[i], maxBytes, chunkSize)
		if err != nil {
			return nil, truncated, true, err
		}
		applied = true
	}

	return current, truncated, applied, nil
}

func decodeContentEncodingLayer(data []byte, encoding string, maxBytes int64, chunkSize int) (decoded []byte, truncated bool, err error) {
	var reader io.ReadCloser
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		reader, err = newDeflateReader(data)
	default:
		return nil, false, errUnsupportedContentEncoding
	}
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = reader.Close()
	}()

	decoded, truncated, err = readWithLimit(reader, maxBytes, chunkSize)
	if truncated && maxBytes > 0 {
		decoded = decoded[:maxBytes]
	}
	return decoded, truncated, err
}

func newDeflateReader(data []byte) (io.ReadCloser, error) {
	if reader, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		return reader, nil
	}
	return flate.NewReader(bytes.NewReader(data)), nil
}

var (
	errUnsupportedContentEncoding = unsupportedContentEncodingError("unsupported content encoding for body analysis")
)

type unsupportedContentEncodingError string

func (e unsupportedContentEncodingError) Error() string {
	return string(e)
}

func parseContentEncodings(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" || part == "identity" {
			continue
		}
		encodings = append(encodings, part)
	}
	return encodings
}

func normalizedContentType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(value)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}

	if idx := strings.IndexByte(value, ';'); idx >= 0 {
		value = value[:idx]
	}

	return strings.ToLower(strings.TrimSpace(value))
}

func containsMethod(methods []string, method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, candidate := range methods {
		if method == candidate {
			return true
		}
	}
	return false
}

func matchesContentType(contentType string, patterns []string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, pattern := range patterns {
		if matchContentTypePattern(contentType, pattern) {
			return true
		}
	}

	return false
}

func matchContentTypePattern(contentType, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}

	if pattern == "*/*" {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(contentType, prefix)
	}

	if idx := strings.IndexByte(pattern, '*'); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return strings.HasPrefix(contentType, prefix) && strings.HasSuffix(contentType, suffix)
	}

	return contentType == pattern
}

func appendWarning(warnings *[]Warning, code, message string) {
	if warnings == nil {
		return
	}

	*warnings = append(*warnings, Warning{
		Code:    code,
		Message: message,
	})
}
