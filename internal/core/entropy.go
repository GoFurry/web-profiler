package core

import (
	"bytes"
	"compress/gzip"
	"math"
)

func analyzeEntropy(sample bodySample, cfg BodyConfig) *EntropyResult {
	if !sample.analyzed {
		return nil
	}

	result := &EntropyResult{
		SampledBytes:       len(sample.sample),
		TotalObservedBytes: int64(len(sample.observed)),
		SampleStrategy:     cfg.SampleStrategy,
	}

	if len(sample.sample) == 0 {
		return result
	}

	var buckets [256]int
	for _, value := range sample.sample {
		buckets[int(value)]++
	}

	total := float64(len(sample.sample))
	repeated := 0
	for _, count := range buckets {
		if count == 0 {
			continue
		}
		result.UniqueByteCount++
		if count > 1 {
			repeated += count - 1
		}
		probability := float64(count) / total
		result.Value -= probability * math.Log2(probability)
	}
	result.NormalizedValue = result.Value / 8.0
	result.RepetitionRatio = float64(repeated) / total
	result.CompressionRatio = estimateCompressionRatio(sample.sample)
	result.ApproxCompressibility = maxFloat64(0, 1-result.CompressionRatio)

	return result
}

func estimateCompressionRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return 0
	}
	if err := writer.Close(); err != nil {
		return 0
	}

	return float64(buffer.Len()) / float64(len(data))
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
