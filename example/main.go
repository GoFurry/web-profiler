package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	webprofiler "github.com/GoFurry/web-profiler"
)

type response struct {
	Path                  string                         `json:"path"`
	Body                  string                         `json:"body"`
	Entropy               *webprofiler.EntropyResult     `json:"entropy,omitempty"`
	Fingerprint           *webprofiler.FingerprintResult `json:"fingerprint,omitempty"`
	Complexity            *webprofiler.ComplexityResult  `json:"complexity,omitempty"`
	Charset               *webprofiler.CharsetResult     `json:"charset,omitempty"`
	Warnings              []webprofiler.Warning          `json:"warnings,omitempty"`
	ContentType           string                         `json:"content_type"`
	ContentLength         int64                          `json:"content_length"`
	ObservedBytes         int64                          `json:"observed_bytes"`
	HeaderCount           int                            `json:"header_count"`
	HeaderBytes           int                            `json:"header_bytes"`
	Sampled               bool                           `json:"sampled"`
	SampleBytes           int                            `json:"sample_bytes"`
	BodyTruncated         bool                           `json:"body_truncated"`
	FingerprintDurationNS int64                          `json:"fingerprint_duration_ns"`
	BodyCaptureDurationNS int64                          `json:"body_capture_duration_ns"`
	EntropyDurationNS     int64                          `json:"entropy_duration_ns"`
	ComplexityDurationNS  int64                          `json:"complexity_duration_ns"`
	CharsetDurationNS     int64                          `json:"charset_duration_ns"`
	AnalysisDuration      string                         `json:"analysis_duration"`
	AnalysisDurationNS    int64                          `json:"analysis_duration_ns"`
}

func main() {
	cfg := webprofiler.DefaultConfig()
	cfg.Fingerprint.IncludeIP = true
	cfg.Fingerprint.TrustProxy = true

	mux := http.NewServeMux()
	mux.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		profile, _ := webprofiler.FromContext(r.Context())

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := response{
			Path:          r.URL.Path,
			Body:          string(body),
			ContentType:   "",
			ContentLength: 0,
		}

		if profile != nil {
			resp.Entropy = profile.Entropy
			resp.Fingerprint = profile.Fingerprint
			resp.Complexity = profile.Complexity
			resp.Charset = profile.Charset
			resp.Warnings = profile.Warnings
			resp.ContentType = profile.Meta.ContentType
			resp.ContentLength = profile.Meta.ContentLength
			resp.ObservedBytes = profile.Meta.ObservedBytes
			resp.HeaderCount = profile.Meta.HeaderCount
			resp.HeaderBytes = profile.Meta.HeaderBytes
			resp.Sampled = profile.Meta.Sampled
			resp.SampleBytes = profile.Meta.SampleBytes
			resp.BodyTruncated = profile.Meta.Truncated
			resp.FingerprintDurationNS = profile.Meta.FingerprintDuration.Nanoseconds()
			resp.BodyCaptureDurationNS = profile.Meta.BodyCaptureDuration.Nanoseconds()
			resp.EntropyDurationNS = profile.Meta.EntropyDuration.Nanoseconds()
			resp.ComplexityDurationNS = profile.Meta.ComplexityDuration.Nanoseconds()
			resp.CharsetDurationNS = profile.Meta.CharsetDuration.Nanoseconds()
			resp.AnalysisDuration = profile.Meta.AnalysisDuration.String()
			resp.AnalysisDurationNS = profile.Meta.AnalysisDuration.Nanoseconds()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	handler := webprofiler.Middleware(cfg)(mux)

	log.Println("listening on http://127.0.0.1:8080")
	log.Println(`try: curl -X POST http://127.0.0.1:8080/inspect -H "Content-Type: application/json" -d "{\"name\":\"alice\",\"tags\":[\"x\",\"y\"]}"`)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
