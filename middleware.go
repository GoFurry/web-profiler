package webprofiler

import (
	"net/http"
	"time"
)

func Middleware(cfg Config) func(http.Handler) http.Handler {
	cfg = normalizeConfig(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			profile := analyzeRequest(r, cfg)
			next.ServeHTTP(w, r.WithContext(withProfile(r.Context(), profile)))
		})
	}
}

func Wrap(next http.Handler, cfg Config) http.Handler {
	return Middleware(cfg)(next)
}

func analyzeRequest(r *http.Request, cfg Config) *Profile {
	start := time.Now()

	profile := &Profile{
		Meta: MetaInfo{
			Method:        r.Method,
			Path:          r.URL.Path,
			ContentType:   normalizedContentType(r.Header.Get("Content-Type")),
			ContentLength: r.ContentLength,
		},
	}
	profile.Meta.HeaderCount, profile.Meta.HeaderBytes = headerStats(r)
	defer func() {
		profile.Meta.AnalysisDuration = time.Since(start)
	}()

	if cfg.EnableFingerprint {
		fingerprintStart := time.Now()
		profile.Fingerprint = analyzeFingerprint(r, cfg.Fingerprint, &profile.Warnings)
		profile.Meta.FingerprintDuration = time.Since(fingerprintStart)
	}

	if !(cfg.EnableEntropy || cfg.EnableComplexity || cfg.EnableCharset) {
		return profile
	}

	bodyCaptureStart := time.Now()
	body := captureBody(r, cfg.Body, &profile.Warnings)
	profile.Meta.BodyCaptureDuration = time.Since(bodyCaptureStart)
	profile.Meta.ObservedBytes = int64(len(body.wireObserved))
	profile.Meta.Sampled = body.sampled
	profile.Meta.SampleBytes = len(body.sample)
	profile.Meta.Truncated = body.truncated

	if cfg.EnableEntropy {
		entropyStart := time.Now()
		profile.Entropy = analyzeEntropy(body, cfg.Body)
		profile.Meta.EntropyDuration = time.Since(entropyStart)
	}

	if cfg.EnableComplexity {
		complexityStart := time.Now()
		profile.Complexity = analyzeComplexity(body, cfg.Complexity, &profile.Warnings)
		profile.Meta.ComplexityDuration = time.Since(complexityStart)
	}

	if cfg.EnableCharset {
		charsetStart := time.Now()
		profile.Charset = analyzeCharset(body, cfg.Charset, &profile.Warnings)
		profile.Meta.CharsetDuration = time.Since(charsetStart)
	}

	return profile
}

func headerStats(r *http.Request) (count int, bytes int) {
	if r == nil {
		return 0, 0
	}

	if r.Host != "" {
		count++
		bytes += len("host") + len(r.Host)
	}

	for key, values := range r.Header {
		for _, value := range values {
			count++
			bytes += len(key) + len(value)
		}
	}

	return count, bytes
}
