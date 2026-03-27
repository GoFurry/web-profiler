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
	defer func() {
		profile.Meta.AnalysisDuration = time.Since(start)
	}()

	if cfg.EnableFingerprint {
		profile.Fingerprint = analyzeFingerprint(r, cfg.Fingerprint, &profile.Warnings)
	}

	if !(cfg.EnableEntropy || cfg.EnableComplexity || cfg.EnableCharset) {
		return profile
	}

	body := captureBody(r, cfg.Body, &profile.Warnings)
	profile.Meta.Sampled = body.sampled
	profile.Meta.SampleBytes = len(body.sample)
	profile.Meta.Truncated = body.truncated

	if cfg.EnableEntropy {
		profile.Entropy = analyzeEntropy(body, cfg.Body)
	}

	if cfg.EnableComplexity {
		profile.Complexity = analyzeComplexity(body, cfg.Complexity, &profile.Warnings)
	}

	if cfg.EnableCharset {
		profile.Charset = analyzeCharset(body, cfg.Charset)
	}

	return profile
}
