package webprofiler

import "math"

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
	for _, count := range buckets {
		if count == 0 {
			continue
		}
		probability := float64(count) / total
		result.Value -= probability * math.Log2(probability)
	}

	return result
}
