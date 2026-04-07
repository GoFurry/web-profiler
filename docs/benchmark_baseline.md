# Benchmark Baseline

This document records a lightweight performance baseline for `web-profiler`.
It is intended as a reference point for future changes, not as a universal promise for every workload.

## Environment

- Date: `2026-04-07`
- OS: `windows`
- Arch: `amd64`
- CPU: `AMD Ryzen 7 5800H with Radeon Graphics`
- Go package: `github.com/GoFurry/web-profiler/internal/core`

## Commands

```bash
go test ./...
go test -run ^$ -bench . ./internal/core
```

## Test Status

- `go test ./...`: passed

## Benchmark Results

| Benchmark | Result |
| --- | --- |
| `BenchmarkAnalyzeComplexityJSONLarge-16` | `1285903 ns/op`, `69.77 MB/s`, `625746 B/op`, `10839 allocs/op` |
| `BenchmarkAnalyzeComplexityXMLLarge-16` | `1080279 ns/op`, `48.54 MB/s`, `392923 B/op`, `9471 allocs/op` |
| `BenchmarkAnalyzeComplexityFormLarge-16` | `224144 ns/op`, `319.75 MB/s`, `152872 B/op`, `976 allocs/op` |
| `BenchmarkAnalyzeComplexityMultipartMetaLarge-16` | `82496 ns/op`, `441.77 MB/s`, `60937 B/op`, `637 allocs/op` |
| `BenchmarkAnalyzeCharsetJSONLarge-16` | `4202800 ns/op`, `14.37 MB/s`, `535425 B/op`, `28679 allocs/op` |
| `BenchmarkAnalyzeFingerprintProxyHeaders-16` | `4068 ns/op`, `3104 B/op`, `48 allocs/op` |
| `BenchmarkCaptureBodyCompressedJSON/gzip-16` | `234634 ns/op`, `8.87 MB/s`, `357910 B/op`, `50 allocs/op` |
| `BenchmarkCaptureBodyCompressedJSON/deflate-16` | `215345 ns/op`, `9.61 MB/s`, `357275 B/op`, `51 allocs/op` |
| `BenchmarkCaptureBodyCompressedJSON/raw_deflate-16` | `166934 ns/op`, `12.36 MB/s`, `357341 B/op`, `51 allocs/op` |
| `BenchmarkCaptureBodyCompressedJSON/gzip_deflate_chain-16` | `180213 ns/op`, `8.34 MB/s`, `407851 B/op`, `85 allocs/op` |
| `BenchmarkAnalyzeRequestLargeJSON-16` | `6885571 ns/op`, `11.94 MB/s`, `2468290 B/op`, `46614 allocs/op` |
| `BenchmarkAnalyzeRequestCompressedJSON-16` | `6886179 ns/op`, `0.30 MB/s`, `2525082 B/op`, `46641 allocs/op` |

## Notes

- `charset` remains one of the heaviest analyzers in this baseline, so future charset changes should be checked against this file.
- End-to-end request analysis stayed close between compressed and uncompressed JSON in this sample, which suggests the current bounded decompression path is stable.
- These numbers depend on payload shape, request headers, Go version, CPU, and OS. Always re-run benchmarks on representative traffic before making production claims.
