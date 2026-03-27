package webprofiler

import (
	"bytes"
	"context"
	"io"
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
