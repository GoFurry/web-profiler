# web-profiler

[![Last Version](https://img.shields.io/github/release/GoFurry/web-profiler/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/web-profiler/releases)
[![License](https://img.shields.io/github/license/GoFurry/coraza-fiber-lite)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.26-blue)](go.mod)

**[中文文档](docs/README_zh.md) | English**

`web-profiler` is a lightweight request analysis middleware for `net/http`.
It inspects incoming requests with bounded overhead, restores the request body for downstream handlers, and exposes structured results through `context.Context`.

It is designed as request-analysis infrastructure, not as a security decision engine.

## 🐲 Highlights

- Native `net/http` middleware API with easy integration into Gin, Chi, Echo, and other `net/http`-based frameworks
- One bounded body capture shared by all analyzers
- Structured request profile exposed through `FromContext`
- Per-request analysis duration with nanosecond precision
- Rich request metadata including observed bytes, header stats, and per-analyzer timings
- Multiple bounded sampling strategies: `head`, `tail`, and `head_tail`
- Optional compressed-body inspection, trusted-proxy CIDR checks, and alternate fingerprint hash algorithms
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

	log.Printf("path=%s content_type=%s observed_bytes=%d", profile.Meta.Path, profile.Meta.ContentType, profile.Meta.ObservedBytes)
	log.Printf("headers=%d header_bytes=%d", profile.Meta.HeaderCount, profile.Meta.HeaderBytes)
	log.Printf("analysis_duration=%s", profile.Meta.AnalysisDuration)
	log.Printf("body=%s", string(body))

	if profile.Entropy != nil {
		log.Printf("entropy=%.4f sample_bytes=%d", profile.Entropy.Value, profile.Entropy.SampledBytes)
	}
	if profile.Fingerprint != nil {
		log.Printf("fingerprint=%s fields=%v", profile.Fingerprint.Hash, profile.Fingerprint.Fields)
	}
	if profile.Complexity != nil {
		log.Printf("complexity_score=%d depth=%d fields=%d scalars=%d", profile.Complexity.Score, profile.Complexity.Depth, profile.Complexity.FieldCount, profile.Complexity.ScalarCount)
	}
	if profile.Charset != nil {
		log.Printf("non_ascii_ratio=%.2f scripts=%v suspicious=%v", profile.Charset.NonASCIIRatio, profile.Charset.UnicodeScriptCounts, profile.Charset.SuspiciousFlags)
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
			"observed":     profile.Meta.ObservedBytes,
			"headers":      profile.Meta.HeaderCount,
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

### `Meta`

- Method, path, normalized content type, and request content length
- Observed body bytes, sample size, truncation state, and header count/bytes
- End-to-end analysis duration plus per-analyzer durations
- Explicit skip and downgrade warnings when body-based analysis does not run

### `Entropy`

- Shannon entropy over the sampled request body bytes
- Normalized entropy, unique-byte count, repetition ratio, and approximate compressibility
- Sample size and observed body size
- Sampling strategy metadata

### `Fingerprint`

- Normalized request headers
- Optional client IP and TLS metadata
- Source flags plus weak/strong hashes with versioning
- Optional hash-only mode when you do not want raw normalized fields in results
- Trusted-proxy CIDR policy and alternate hash algorithms such as `sha1`, `sha256`, `sha512`, and `fnv1a64`

### `Complexity`

- JSON depth, field counts, scalar/null/string stats, and key-length summaries
- Object/array counts, max array length, and max object width
- URL-encoded form statistics plus key/value length summaries
- Optional multipart file metadata such as file counts, extensions, and content types
- Interpretable score factors

### `Charset`

- ASCII, digit, whitespace, symbol, control, and non-ASCII ratios
- Emoji ratio and invisible-character density
- Unicode script distribution counts when enabled
- Optional confusable/homoglyph detection and format-specific metrics for JSON, XML, and form payloads
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
cfg.Body.SampleStrategy = webprofiler.SampleStrategyHeadTail
cfg.Body.EnableCompressedAnalysis = true
cfg.Fingerprint.IncludeIP = true
cfg.Fingerprint.TrustProxy = true
cfg.Fingerprint.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
cfg.Fingerprint.HashAlgorithm = "sha512"
cfg.Fingerprint.ExposeFields = false
cfg.Complexity.MaxJSONDepth = 16
cfg.Complexity.EnableMultipartMeta = true
cfg.Charset.EnableConfusableDetection = true
cfg.Charset.EnableFormatSpecificMetrics = true
```

## Performance Notes

- `MetaInfo.AnalysisDuration` records middleware analysis time as `time.Duration`
- `MetaInfo` now also exposes per-analyzer timings so you can see where request profiling time is spent
- The example exposes both `analysis_duration` and `analysis_duration_ns` so you can read it directly or aggregate it precisely
- The SHA-256 fingerprint step hashes a very small normalized string built from a few headers and optional TLS/IP fields, so in most cases it is not the main cost
- Alternate fingerprint hash algorithms are available, but `sha256` remains the best default tradeoff for compatibility and stability
- Compressed-body inspection is optional because it adds decompression work; enable it when encoded request payloads are common in your traffic
- If you want the cheapest possible fingerprint output, set `Fingerprint.ExposeFields = false` to keep only hashes and source metadata
- In practice, request-body capture, JSON parsing, and charset scanning are usually more expensive than the final SHA-256 call
- If you run at very high QPS, benchmark with your own traffic and disable `EnableFingerprint`, `IncludeIP`, or `IncludeTLS` if you want an even cheaper profile

## Example Response Fields

The native example at [`example/main.go`](example/main.go) returns a JSON payload like the one you posted. The following table maps each field to its meaning:

| Field | Meaning |
| --- | --- |
| `path` | Request path seen by the middleware and handler. |
| `body` | Request body re-read inside the handler, proving the middleware restored `r.Body`. |
| `observed_bytes` | Number of body bytes actually observed before sampling. |
| `header_count` | Number of request header entries counted by the middleware, including `Host`. |
| `header_bytes` | Approximate size of header keys and values counted by the middleware. |
| `entropy.Value` | Shannon entropy of the sampled body bytes. Higher usually means more byte diversity. |
| `entropy.NormalizedValue` | Entropy normalized to an approximate `0..1` range by dividing by `8 bits/byte`. |
| `entropy.SampledBytes` | Number of bytes used for entropy calculation. |
| `entropy.TotalObservedBytes` | Number of body bytes observed by the middleware before sampling. |
| `entropy.UniqueByteCount` | Number of distinct byte values seen in the sampled body. |
| `entropy.RepetitionRatio` | Share of sampled bytes that repeat beyond their first occurrence. |
| `entropy.CompressionRatio` | Approximate gzip-compressed size divided by sampled size. Lower often means more repetitive content. |
| `entropy.ApproxCompressibility` | A convenience score derived from the compression ratio. Higher usually means easier-to-compress content. |
| `entropy.SampleStrategy` | Sampling mode currently used for body analysis. |
| `fingerprint.Fields` | Normalized fields used to build the request fingerprint. |
| `fingerprint.SourceFlags` | Which input sources contributed to the fingerprint, for example `headers`, `tls`, or `ip`. |
| `fingerprint.Hash` | Stable SHA-256 digest of the normalized fingerprint fields. |
| `fingerprint.WeakHash` | Fingerprint hash that excludes more volatile inputs such as client IP. |
| `fingerprint.StrongHash` | Fingerprint hash built from the full configured input set. |
| `fingerprint.HashAlgorithm` | Fingerprint hash algorithm currently used. |
| `fingerprint.HashVersion` | Fingerprint schema/version identifier. |
| `complexity.ContentType` | Content type used for complexity analysis. |
| `complexity.Depth` | Observed structural depth of the parsed body. Depth is counted on the recursive walk, so scalar leaf values increase the final depth level. |
| `complexity.FieldCount` | Total number of parsed fields/values. |
| `complexity.ObjectCount` | Number of JSON objects encountered. |
| `complexity.ArrayCount` | Number of arrays encountered. |
| `complexity.ScalarCount` | Number of non-container values such as strings, numbers, booleans, and `null`. |
| `complexity.NullCount` | Number of `null` values seen in JSON. |
| `complexity.StringCount` | Number of string values seen in the parsed payload. |
| `complexity.UniqueKeyCount` | Number of keys encountered across parsed objects or form keys. |
| `complexity.MaxArrayLength` | Longest array length seen in the body. |
| `complexity.MaxObjectFields` | Largest number of fields found in a single object or form key set. |
| `complexity.MaxKeyLength` | Longest key length seen during complexity analysis. |
| `complexity.MaxStringLength` | Longest JSON string value length seen during complexity analysis. |
| `complexity.MaxValueLength` | Longest form value length seen during complexity analysis. |
| `complexity.AverageKeyLength` | Average key length for form inputs. |
| `complexity.AverageValueLength` | Average value length for form inputs. |
| `complexity.MultipartFileCount` | Number of uploaded files seen in multipart metadata mode. |
| `complexity.MultipartFieldCount` | Number of non-file form fields seen in multipart metadata mode. |
| `complexity.MultipartFileExtensions` | Count of file extensions seen across multipart uploads. |
| `complexity.MultipartFileContentTypes` | Count of per-file content types seen in multipart uploads. |
| `complexity.MultipartMaxFileNameLength` | Longest multipart file name length seen in the request. |
| `complexity.Score` | Aggregate complexity score. |
| `complexity.ScoreFactors` | Breakdown of how the complexity score was calculated. |
| `charset.TotalChars` | Total characters scanned in the sampled text body. |
| `charset.ASCIIAlphaRatio` | Ratio of ASCII letters in the sampled body. |
| `charset.DigitRatio` | Ratio of digits in the sampled body. |
| `charset.WhitespaceRatio` | Ratio of whitespace characters in the sampled body. |
| `charset.SymbolRatio` | Ratio of punctuation and symbol characters in the sampled body. |
| `charset.ControlCharRatio` | Ratio of control characters or invalid byte sequences. |
| `charset.NonASCIIRatio` | Ratio of non-ASCII characters in the sampled body. |
| `charset.EmojiRatio` | Ratio of emoji-like code points in the sampled text. |
| `charset.InvisibleCharRatio` | Ratio of invisible characters such as zero-width marks or formatting controls. |
| `charset.ConfusableCount` | Number of characters that match a built-in homoglyph/confusable set. |
| `charset.UnicodeScriptCounts` | Count of characters per detected Unicode script when script detection is enabled. |
| `charset.FormatMetrics` | Optional format-aware metrics for JSON, XML, or form payloads, such as token counts and repeated keys. |
| `charset.SuspiciousFlags` | Optional markers such as invalid UTF-8, zero-width characters, or mixed scripts. |
| `content_type` | Normalized request `Content-Type`. |
| `content_length` | Request body length reported by the incoming request. |
| `sampled` | Whether the middleware analyzed only a subset of the observed body. |
| `sample_bytes` | Number of sampled bytes actually used by body analyzers. |
| `body_truncated` | Whether body observation stopped at `MaxReadBytes`. |
| `fingerprint_duration_ns` | Time spent building the request fingerprint. |
| `body_capture_duration_ns` | Time spent capturing and replaying the request body. |
| `entropy_duration_ns` | Time spent calculating body entropy. |
| `complexity_duration_ns` | Time spent calculating complexity metrics. |
| `charset_duration_ns` | Time spent calculating charset metrics. |
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

Repository layout is intentionally simple:

- root package: stable middleware API for callers
- `example/`: runnable demo program
- `internal/policy`: config types and normalization
- `internal/model`: profile and result types
- `internal/core`: request capture, analyzers, and context plumbing

## Testing

```bash
go test ./...
```

The test suite covers middleware behavior, body replay, config normalization, analyzer outputs, and warning paths.

## 🐺 License

This project is open-sourced under the [MIT License](LICENSE), which permits commercial use, modification, and distribution without requiring the original author's copyright notice to be retained.
