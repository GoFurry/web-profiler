package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFromContextHandlesNilAndMissingProfile(t *testing.T) {
	if profile, ok := FromContext(nil); ok || profile != nil {
		t.Fatalf("FromContext(nil) = (%v, %v), want (nil, false)", profile, ok)
	}

	if profile, ok := FromContext(context.Background()); ok || profile != nil {
		t.Fatalf("FromContext(background) = (%v, %v), want (nil, false)", profile, ok)
	}
}

func TestMiddlewareInjectsProfileAndPreservesBody(t *testing.T) {
	payload := `{"a":[{"b":1},{"c":2}],"d":{"e":"hi"}}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/profile", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	var gotProfile *Profile
	var gotBody string

	handler := Middleware(DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := FromContext(r.Context())
		if !ok || profile == nil {
			t.Fatal("expected profile to be present in the request context")
		}
		gotProfile = profile

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read replayed body: %v", err)
		}
		gotBody = string(body)

		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("unexpected status code: got %d want %d", recorder.Code, http.StatusAccepted)
	}

	if gotBody != payload {
		t.Fatalf("middleware should preserve the original body: got %q want %q", gotBody, payload)
	}

	if gotProfile.Meta.Method != http.MethodPost {
		t.Fatalf("unexpected method: got %q want %q", gotProfile.Meta.Method, http.MethodPost)
	}

	if gotProfile.Meta.Path != "/api/profile" {
		t.Fatalf("unexpected path: got %q want %q", gotProfile.Meta.Path, "/api/profile")
	}

	if gotProfile.Meta.ContentType != "application/json" {
		t.Fatalf("unexpected content type: got %q want %q", gotProfile.Meta.ContentType, "application/json")
	}

	if gotProfile.Meta.ContentLength != int64(len(payload)) {
		t.Fatalf("unexpected content length: got %d want %d", gotProfile.Meta.ContentLength, len(payload))
	}

	if gotProfile.Meta.ObservedBytes != int64(len(payload)) {
		t.Fatalf("unexpected observed bytes: got %d want %d", gotProfile.Meta.ObservedBytes, len(payload))
	}

	if gotProfile.Meta.HeaderCount < 2 {
		t.Fatalf("expected at least host and content-type to be counted, got %d", gotProfile.Meta.HeaderCount)
	}

	if gotProfile.Meta.HeaderBytes <= 0 {
		t.Fatalf("header bytes should be positive, got %d", gotProfile.Meta.HeaderBytes)
	}

	if gotProfile.Meta.Sampled {
		t.Fatal("request should not be marked as sampled when the body is smaller than SampleBytes")
	}

	if gotProfile.Meta.SampleBytes != len(payload) {
		t.Fatalf("unexpected sample size: got %d want %d", gotProfile.Meta.SampleBytes, len(payload))
	}

	if gotProfile.Meta.Truncated {
		t.Fatal("request should not be marked as truncated")
	}

	if gotProfile.Meta.AnalysisDuration < 0 {
		t.Fatalf("analysis duration should never be negative, got %s", gotProfile.Meta.AnalysisDuration)
	}

	if gotProfile.Meta.FingerprintDuration < 0 ||
		gotProfile.Meta.BodyCaptureDuration < 0 ||
		gotProfile.Meta.EntropyDuration < 0 ||
		gotProfile.Meta.ComplexityDuration < 0 ||
		gotProfile.Meta.CharsetDuration < 0 {
		t.Fatalf("per-analyzer durations should never be negative: %+v", gotProfile.Meta)
	}

	if gotProfile.Entropy == nil {
		t.Fatal("expected entropy result to be populated")
	}

	if gotProfile.Fingerprint == nil {
		t.Fatal("expected fingerprint result to be populated")
	}

	if gotProfile.Complexity == nil {
		t.Fatal("expected complexity result to be populated")
	}

	if gotProfile.Charset == nil {
		t.Fatal("expected charset result to be populated")
	}

	if gotProfile.Complexity.Depth != 4 {
		t.Fatalf("unexpected JSON depth: got %d want 4", gotProfile.Complexity.Depth)
	}

	if len(gotProfile.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", gotProfile.Warnings)
	}
}

func TestWrapProvidesConvenienceMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")

	called := false
	handler := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := FromContext(r.Context()); !ok {
			t.Fatal("expected profile to be attached by Wrap")
		}
		w.WriteHeader(http.StatusNoContent)
	}), DefaultConfig())

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !called {
		t.Fatal("wrapped handler was not invoked")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("unexpected status code: got %d want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestCaptureBodyTruncatesAndReplaysFullBody(t *testing.T) {
	payload := "abcdefghi"
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	var warnings []Warning
	sample := captureBody(req, BodyConfig{
		MaxReadBytes:        5,
		SampleBytes:         3,
		SampleStrategy:      SampleStrategyHead,
		AnalyzeMethods:      []string{http.MethodPost},
		AnalyzeContentTypes: []string{"application/json"},
	}, &warnings)

	if !sample.analyzed {
		t.Fatal("expected body to be analyzed")
	}

	if string(sample.observed) != "abcde" {
		t.Fatalf("unexpected observed bytes: got %q want %q", string(sample.observed), "abcde")
	}

	if string(sample.sample) != "abc" {
		t.Fatalf("unexpected sample bytes: got %q want %q", string(sample.sample), "abc")
	}

	if !sample.sampled {
		t.Fatal("expected request to be marked as sampled")
	}

	if !sample.truncated {
		t.Fatal("expected request to be marked as truncated")
	}

	if !hasWarningCode(warnings, "body_truncated") {
		t.Fatalf("expected body_truncated warning, got %+v", warnings)
	}

	replayedBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read replayed request body: %v", err)
	}

	if string(replayedBody) != payload {
		t.Fatalf("unexpected replayed body: got %q want %q", string(replayedBody), payload)
	}
}

func TestCaptureBodyAddsSkipWarnings(t *testing.T) {
	t.Run("method filtered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search", strings.NewReader("name=alice"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var warnings []Warning
		sample := captureBody(req, BodyConfig{
			MaxReadBytes:        1024,
			SampleBytes:         128,
			SampleStrategy:      SampleStrategyHead,
			AnalyzeMethods:      []string{http.MethodPost},
			AnalyzeContentTypes: []string{"application/x-www-form-urlencoded"},
		}, &warnings)

		if sample.analyzed {
			t.Fatal("sample should not be analyzed when the method is filtered")
		}

		if !hasWarningCode(warnings, "body_skipped_method") {
			t.Fatalf("expected body_skipped_method warning, got %+v", warnings)
		}
	})

	t.Run("content type filtered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader("binary"))
		req.Header.Set("Content-Type", "application/octet-stream")

		var warnings []Warning
		sample := captureBody(req, BodyConfig{
			MaxReadBytes:        1024,
			SampleBytes:         128,
			SampleStrategy:      SampleStrategyHead,
			AnalyzeMethods:      []string{http.MethodPost},
			AnalyzeContentTypes: []string{"application/json"},
		}, &warnings)

		if sample.analyzed {
			t.Fatal("sample should not be analyzed when the content type is filtered")
		}

		if !hasWarningCode(warnings, "body_skipped_content_type") {
			t.Fatalf("expected body_skipped_content_type warning, got %+v", warnings)
		}
	})
}

func TestBuildSampleSupportsTailAndHeadTailStrategies(t *testing.T) {
	observed := []byte("abcdefghij")

	tailSample, tailSampled := buildSample(observed, 4, SampleStrategyTail)
	if !tailSampled || string(tailSample) != "ghij" {
		t.Fatalf("tail sample = (%q, %v), want (%q, true)", string(tailSample), tailSampled, "ghij")
	}

	headTailSample, headTailSampled := buildSample(observed, 5, SampleStrategyHeadTail)
	if !headTailSampled || string(headTailSample) != "abcij" {
		t.Fatalf("head_tail sample = (%q, %v), want (%q, true)", string(headTailSample), headTailSampled, "abcij")
	}
}

func TestCaptureBodySupportsCompressedAnalysisAndStreamingRead(t *testing.T) {
	plainPayload := `{"msg":"hello","tags":["x","y"]}`

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(plainPayload)); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	var warnings []Warning
	sample := captureBody(req, BodyConfig{
		MaxReadBytes:             int64(compressed.Len()),
		MaxDecompressedBytes:     1024,
		StreamReadChunkSize:      3,
		SampleBytes:              64,
		SampleStrategy:           SampleStrategyHead,
		EnableCompressedAnalysis: true,
		AnalyzeMethods:           []string{http.MethodPost},
		AnalyzeContentTypes:      []string{"application/json"},
	}, &warnings)

	if !sample.analyzed {
		t.Fatal("expected compressed body to be analyzed")
	}

	if !sample.decoded {
		t.Fatal("expected compressed body analysis to decode the payload")
	}

	if !bytes.Equal(sample.wireObserved, compressed.Bytes()) {
		t.Fatalf("unexpected wire-observed bytes")
	}

	if string(sample.observed) != plainPayload {
		t.Fatalf("unexpected decoded observed payload: got %q want %q", string(sample.observed), plainPayload)
	}

	if string(sample.sample) != plainPayload {
		t.Fatalf("unexpected decoded sample payload: got %q want %q", string(sample.sample), plainPayload)
	}

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	replayedBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read replayed request body: %v", err)
	}

	if !bytes.Equal(replayedBody, compressed.Bytes()) {
		t.Fatal("replayed request body should preserve the original compressed payload")
	}
}

func TestAnalyzeRequestSkipsStructuredAnalysisForEncodedBodyWhenCompressedAnalysisIsDisabled(t *testing.T) {
	plainPayload := `{"msg":"hello"}`

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(plainPayload)); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	cfg := DefaultConfig()
	cfg.Body.EnableCompressedAnalysis = false

	profile := analyzeRequest(req, cfg)
	if profile == nil {
		t.Fatal("expected profile")
	}

	if profile.Entropy == nil {
		t.Fatal("expected entropy result on observed bytes")
	}

	if profile.Complexity != nil {
		t.Fatalf("expected complexity analysis to be skipped for encoded body, got %+v", profile.Complexity)
	}

	if profile.Charset != nil {
		t.Fatalf("expected charset analysis to be skipped for encoded body, got %+v", profile.Charset)
	}

	if !hasWarningCode(profile.Warnings, "body_encoded_not_decoded") {
		t.Fatalf("expected body_encoded_not_decoded warning, got %+v", profile.Warnings)
	}
}

func TestAnalyzeRequestDoesNotSkipIdentityEncodedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(`{"msg":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "identity")

	cfg := DefaultConfig()
	profile := analyzeRequest(req, cfg)
	if profile == nil {
		t.Fatal("expected profile")
	}

	if profile.Complexity == nil {
		t.Fatal("expected complexity analysis to run for identity-encoded body")
	}

	if profile.Charset == nil {
		t.Fatal("expected charset analysis to run for identity-encoded body")
	}

	if hasWarningCode(profile.Warnings, "body_encoded_not_decoded") {
		t.Fatalf("did not expect body_encoded_not_decoded warning, got %+v", profile.Warnings)
	}
}

func TestAnalyzeRequestSupportsMultipartMetaWithDocumentedConfig(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", bytes.NewReader(payload.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	cfg := DefaultConfig()
	cfg.Complexity.EnableMultipartMeta = true
	cfg = normalizeConfig(cfg)

	profile := analyzeRequest(req, cfg)
	if profile == nil || profile.Complexity == nil {
		t.Fatalf("expected multipart complexity result, got %+v", profile)
	}

	if profile.Complexity.MultipartFileCount != 1 || profile.Complexity.MultipartFieldCount != 1 {
		t.Fatalf("unexpected multipart complexity stats: %+v", profile.Complexity)
	}
}

func TestReadWithLimitReturnsNoProgressError(t *testing.T) {
	data, truncated, err := readWithLimit(zeroReader{}, 16, 4)

	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("expected io.ErrNoProgress, got %v", err)
	}

	if truncated {
		t.Fatal("did not expect truncated result")
	}

	if len(data) != 0 {
		t.Fatalf("expected no data, got %q", string(data))
	}
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) {
	return 0, nil
}
