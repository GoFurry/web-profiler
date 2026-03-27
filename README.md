# web-profiler

[![Last Version](https://img.shields.io/github/release/GoFurry/web-profiler/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/web-profiler/releases)
[![License](https://img.shields.io/github/license/GoFurry/coraza-fiber-lite)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.26-blue)](go.mod)

**[中文文档](README_zh.md) | English**

`web-profiler` is a lightweight request analysis middleware for `net/http`.
It inspects incoming requests with bounded overhead, restores the request body for downstream handlers, and exposes structured results through `context.Context`.

It is designed as request-analysis infrastructure, not as a security decision engine.

## 🐲 Highlights

- Native `net/http` middleware API with easy integration into Gin, Chi, Echo, and other `net/http`-based frameworks
- One bounded body capture shared by all analyzers
- Structured request profile exposed through `FromContext`
- Per-request analysis duration with nanosecond precision
- Safe degradation with warnings instead of failing the request
- Built-in analyzers for entropy, fingerprint, complexity, and charset distribution

## Installation

```bash
go get github.com/GoFurry/web-profiler
```

## 🚀 Quick Start

```go
package main

import (
	"log"
	"net/http"

	webprofiler "github.com/GoFurry/web-profiler"
)

func main() {
	cfg := webprofiler.DefaultConfig()

	handler := webprofiler.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := webprofiler.FromContext(r.Context())
		if ok && profile != nil {
			if profile.Entropy != nil {
				log.Printf("entropy=%.4f", profile.Entropy.Value)
			}
			if profile.Fingerprint != nil {
				log.Printf("fingerprint=%s", profile.Fingerprint.Hash)
			}
		}

		// The request body is still readable here.
		w.WriteHeader(http.StatusOK)
	}))

	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

You can also use the convenience helper:

```go
handler := webprofiler.Wrap(mux, webprofiler.DefaultConfig())
```

A runnable native `net/http` example lives at [`example/main.go`](example/main.go).

## Using Profile Data In Handlers

`FromContext` gives you the collected `Profile`. You can inspect metadata, module outputs, and warnings inside any downstream handler:

```go
func inspectHandler(w http.ResponseWriter, r *http.Request) {
	profile, ok := webprofiler.FromContext(r.Context())
	if !ok || profile == nil {
		http.Error(w, "profile not found", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("path=%s content_type=%s", profile.Meta.Path, profile.Meta.ContentType)
	log.Printf("analysis_duration=%s", profile.Meta.AnalysisDuration)
	log.Printf("body=%s", string(body))

	if profile.Entropy != nil {
		log.Printf("entropy=%.4f sample_bytes=%d", profile.Entropy.Value, profile.Entropy.SampledBytes)
	}
	if profile.Fingerprint != nil {
		log.Printf("fingerprint=%s fields=%v", profile.Fingerprint.Hash, profile.Fingerprint.Fields)
	}
	if profile.Complexity != nil {
		log.Printf("complexity_score=%d depth=%d fields=%d", profile.Complexity.Score, profile.Complexity.Depth, profile.Complexity.FieldCount)
	}
	if profile.Charset != nil {
		log.Printf("non_ascii_ratio=%.2f suspicious=%v", profile.Charset.NonASCIIRatio, profile.Charset.SuspiciousFlags)
	}
	if len(profile.Warnings) > 0 {
		log.Printf("warnings=%v", profile.Warnings)
	}

	w.WriteHeader(http.StatusOK)
}
```

## Gin Example

Gin uses `net/http` under the hood, so you can wrap its engine directly:

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	webprofiler "github.com/GoFurry/web-profiler"
)

func main() {
	cfg := webprofiler.DefaultConfig()
	engine := gin.New()

	engine.POST("/inspect", func(c *gin.Context) {
		profile, ok := webprofiler.FromContext(c.Request.Context())
		if !ok || profile == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "profile not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"path":         profile.Meta.Path,
			"content_type": profile.Meta.ContentType,
			"analysis_ns":  profile.Meta.AnalysisDuration.Nanoseconds(),
			"entropy":      profile.Entropy,
			"fingerprint":  profile.Fingerprint,
			"complexity":   profile.Complexity,
			"charset":      profile.Charset,
			"warnings":     profile.Warnings,
		})
	})

	handler := webprofiler.Middleware(cfg)(engine)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

## Public API

```go
func Middleware(cfg Config) func(http.Handler) http.Handler
func Wrap(next http.Handler, cfg Config) http.Handler
func DefaultConfig() Config
func FromContext(ctx context.Context) (*Profile, bool)
```

## What Gets Collected

### `Entropy`

- Shannon entropy over the sampled request body bytes
- Sample size and observed body size
- Sampling strategy metadata

### `Fingerprint`

- Normalized request headers
- Optional client IP and TLS metadata
- Stable hashed fingerprint with versioning

### `Complexity`

- JSON depth and field counts
- Object/array counts and max array length
- URL-encoded form statistics
- Interpretable score factors

### `Charset`

- ASCII, digit, whitespace, symbol, control, and non-ASCII ratios
- Optional suspicious flags such as invalid UTF-8, zero-width characters, and mixed scripts

## 🧭 Configuration

`DefaultConfig()` returns a ready-to-use setup with bounded defaults:

- `BodyConfig` limits read size, sample size, methods, and content types
- `FingerprintConfig` controls headers, proxy trust, TLS metadata, and hash versioning
- `ComplexityConfig` controls JSON depth, field limits, and supported content types
- `CharsetConfig` controls text analysis size and suspicious-pattern detection

Typical customization:

```go
cfg := webprofiler.DefaultConfig()
cfg.Body.MaxReadBytes = 64 << 10
cfg.Body.SampleBytes = 8 << 10
cfg.Fingerprint.IncludeIP = true
cfg.Fingerprint.TrustProxy = true
cfg.Complexity.MaxJSONDepth = 16
```

## Performance Notes

- `MetaInfo.AnalysisDuration` records middleware analysis time as `time.Duration`
- The example exposes both `analysis_duration` and `analysis_duration_ns` so you can read it directly or aggregate it precisely
- The SHA-256 fingerprint step hashes a very small normalized string built from a few headers and optional TLS/IP fields, so in most cases it is not the main cost
- In practice, request-body capture, JSON parsing, and charset scanning are usually more expensive than the final SHA-256 call
- If you run at very high QPS, benchmark with your own traffic and disable `EnableFingerprint`, `IncludeIP`, or `IncludeTLS` if you want an even cheaper profile

## Example Response Fields

The native example at [`example/main.go`](example/main.go) returns a JSON payload like the one you posted. The following table maps each field to its meaning:

| Field | Meaning |
| --- | --- |
| `path` | Request path seen by the middleware and handler. |
| `body` | Request body re-read inside the handler, proving the middleware restored `r.Body`. |
| `entropy.Value` | Shannon entropy of the sampled body bytes. Higher usually means more byte diversity. |
| `entropy.SampledBytes` | Number of bytes used for entropy calculation. |
| `entropy.TotalObservedBytes` | Number of body bytes observed by the middleware before sampling. |
| `entropy.SampleStrategy` | Sampling mode currently used for body analysis. |
| `fingerprint.Fields` | Normalized fields used to build the request fingerprint. |
| `fingerprint.Hash` | Stable SHA-256 digest of the normalized fingerprint fields. |
| `fingerprint.HashAlgorithm` | Fingerprint hash algorithm currently used. |
| `fingerprint.HashVersion` | Fingerprint schema/version identifier. |
| `complexity.ContentType` | Content type used for complexity analysis. |
| `complexity.Depth` | Observed structural depth of the parsed body. |
| `complexity.FieldCount` | Total number of parsed fields/values. |
| `complexity.ObjectCount` | Number of JSON objects encountered. |
| `complexity.ArrayCount` | Number of arrays encountered. |
| `complexity.MaxArrayLength` | Longest array length seen in the body. |
| `complexity.Score` | Aggregate complexity score. |
| `complexity.ScoreFactors` | Breakdown of how the complexity score was calculated. |
| `charset.TotalChars` | Total characters scanned in the sampled text body. |
| `charset.ASCIIAlphaRatio` | Ratio of ASCII letters in the sampled body. |
| `charset.DigitRatio` | Ratio of digits in the sampled body. |
| `charset.WhitespaceRatio` | Ratio of whitespace characters in the sampled body. |
| `charset.SymbolRatio` | Ratio of punctuation and symbol characters in the sampled body. |
| `charset.ControlCharRatio` | Ratio of control characters or invalid byte sequences. |
| `charset.NonASCIIRatio` | Ratio of non-ASCII characters in the sampled body. |
| `charset.SuspiciousFlags` | Optional markers such as invalid UTF-8, zero-width characters, or mixed scripts. |
| `content_type` | Normalized request `Content-Type`. |
| `content_length` | Request body length reported by the incoming request. |
| `sampled` | Whether the middleware analyzed only a subset of the observed body. |
| `sample_bytes` | Number of sampled bytes actually used by body analyzers. |
| `body_truncated` | Whether body observation stopped at `MaxReadBytes`. |
| `analysis_duration` | Human-readable middleware analysis duration, for example `187.4µs`. |
| `analysis_duration_ns` | Exact middleware analysis duration in nanoseconds, useful for metrics and aggregation. |

## 🌟 Design Boundaries

This middleware:

- analyzes requests, not responses
- does not persist or export results
- does not block traffic on analyzer failures
- does not guarantee deep parsing for every content type
- does not produce business risk decisions

## Result Model

Each request produces a `Profile`:

```go
type Profile struct {
	Meta        MetaInfo
	Entropy     *EntropyResult
	Fingerprint *FingerprintResult
	Complexity  *ComplexityResult
	Charset     *CharsetResult
	Warnings    []Warning
}
```

Analyzer results are optional pointers so handlers can distinguish between disabled, skipped, and populated modules.

## Testing

```bash
go test ./...
```

The test suite covers middleware behavior, body replay, config normalization, analyzer outputs, and warning paths.

## 🐺 License

This project is open-sourced under the [MIT License](LICENSE), which permits commercial use, modification, and distribution without requiring the original author's copyright notice to be retained.
