package webprofiler

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

type bodySample struct {
	contentType string
	rawType     string
	observed    []byte
	sample      []byte
	sampled     bool
	truncated   bool
	analyzed    bool
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

func captureBody(r *http.Request, cfg BodyConfig, warnings *[]Warning) bodySample {
	rawType := r.Header.Get("Content-Type")
	sample := bodySample{
		contentType: normalizedContentType(rawType),
		rawType:     rawType,
	}

	if r.Body == nil || r.Body == http.NoBody {
		return sample
	}

	if !containsMethod(cfg.AnalyzeMethods, r.Method) {
		return sample
	}

	if !matchesContentType(sample.contentType, cfg.AnalyzeContentTypes) {
		return sample
	}

	consumed, observed, truncated, err := readLimitedBody(r.Body, cfg.MaxReadBytes)
	r.Body = replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(consumed), r.Body),
		closer: r.Body,
	}

	sample.analyzed = true
	sample.observed = observed
	sample.truncated = truncated

	if cfg.SampleBytes < len(observed) {
		sample.sample = append([]byte(nil), observed[:cfg.SampleBytes]...)
		sample.sampled = true
	} else {
		sample.sample = append([]byte(nil), observed...)
	}

	if truncated {
		appendWarning(warnings, "body_truncated", "request body observation reached MaxReadBytes and was truncated")
	}

	if err != nil {
		appendWarning(warnings, "body_read_error", err.Error())
	}

	return sample
}

func readLimitedBody(body io.ReadCloser, maxReadBytes int64) (consumed []byte, observed []byte, truncated bool, err error) {
	if maxReadBytes <= 0 {
		return nil, nil, false, nil
	}

	consumed, err = io.ReadAll(io.LimitReader(body, maxReadBytes+1))
	observed = consumed
	if int64(len(consumed)) > maxReadBytes {
		truncated = true
		observed = consumed[:maxReadBytes]
	}

	return consumed, observed, truncated, err
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
