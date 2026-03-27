package webprofiler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
)

var (
	errComplexityDepthExceeded = errors.New("maximum JSON depth exceeded")
	errComplexityFieldExceeded = errors.New("maximum field count exceeded")
)

type jsonComplexityStats struct {
	depth          int
	fieldCount     int
	objectCount    int
	arrayCount     int
	maxArrayLength int
}

func analyzeComplexity(sample bodySample, cfg ComplexityConfig, warnings *[]Warning) *ComplexityResult {
	if !sample.analyzed || len(sample.observed) == 0 {
		return nil
	}

	if !matchesContentType(sample.contentType, cfg.SupportedContentTypes) {
		return nil
	}

	switch {
	case matchContentTypePattern(sample.contentType, "application/json"),
		matchContentTypePattern(sample.contentType, "application/*+json"):
		return analyzeJSONComplexity(sample, cfg, warnings)
	case sample.contentType == "application/x-www-form-urlencoded" && cfg.EnableFormAnalysis:
		return analyzeFormComplexity(sample.observed)
	case sample.contentType == "multipart/form-data" && cfg.EnableMultipartMeta:
		return analyzeMultipartComplexity(sample, warnings)
	default:
		return nil
	}
}

func analyzeJSONComplexity(sample bodySample, cfg ComplexityConfig, warnings *[]Warning) *ComplexityResult {
	var payload any

	decoder := json.NewDecoder(bytes.NewReader(sample.observed))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		appendWarning(warnings, "complexity_parse_failed", err.Error())
		return nil
	}

	stats := jsonComplexityStats{}
	if err := walkJSONComplexity(payload, 1, cfg, &stats); err != nil {
		appendWarning(warnings, "complexity_limit_exceeded", err.Error())
	}

	factors := []ScoreFactor{
		{Name: "depth", Value: stats.depth},
		{Name: "fields", Value: minInt(stats.fieldCount/10, 20)},
		{Name: "arrays", Value: minInt(stats.arrayCount*2, 20)},
		{Name: "max_array_length", Value: minInt(stats.maxArrayLength/10, 20)},
	}

	return &ComplexityResult{
		ContentType:    sample.contentType,
		Depth:          stats.depth,
		FieldCount:     stats.fieldCount,
		ObjectCount:    stats.objectCount,
		ArrayCount:     stats.arrayCount,
		MaxArrayLength: stats.maxArrayLength,
		Score:          sumScoreFactors(factors),
		ScoreFactors:   factors,
	}
}

func walkJSONComplexity(value any, depth int, cfg ComplexityConfig, stats *jsonComplexityStats) error {
	if depth > cfg.MaxJSONDepth {
		return errComplexityDepthExceeded
	}

	if depth > stats.depth {
		stats.depth = depth
	}

	switch typed := value.(type) {
	case map[string]any:
		stats.objectCount++
		stats.fieldCount += len(typed)
		if stats.fieldCount > cfg.MaxFields {
			return errComplexityFieldExceeded
		}
		for _, child := range typed {
			if err := walkJSONComplexity(child, depth+1, cfg, stats); err != nil {
				return err
			}
		}
	case []any:
		stats.arrayCount++
		if len(typed) > stats.maxArrayLength {
			stats.maxArrayLength = len(typed)
		}
		for _, child := range typed {
			if err := walkJSONComplexity(child, depth+1, cfg, stats); err != nil {
				return err
			}
		}
	}

	return nil
}

func analyzeFormComplexity(data []byte) *ComplexityResult {
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return nil
	}

	fieldCount := 0
	repeatedKeys := 0
	maxArrayLength := 0
	for _, values := range values {
		fieldCount += len(values)
		if len(values) > 1 {
			repeatedKeys++
		}
		if len(values) > maxArrayLength {
			maxArrayLength = len(values)
		}
	}

	factors := []ScoreFactor{
		{Name: "fields", Value: minInt(fieldCount/10, 20)},
		{Name: "repeated_keys", Value: repeatedKeys},
		{Name: "max_values_per_key", Value: minInt(maxArrayLength, 20)},
	}

	return &ComplexityResult{
		ContentType:    "application/x-www-form-urlencoded",
		Depth:          1,
		FieldCount:     fieldCount,
		ObjectCount:    1,
		ArrayCount:     repeatedKeys,
		MaxArrayLength: maxArrayLength,
		Score:          sumScoreFactors(factors),
		ScoreFactors:   factors,
	}
}

func analyzeMultipartComplexity(sample bodySample, warnings *[]Warning) *ComplexityResult {
	_, params, err := mime.ParseMediaType(sample.rawType)
	if err != nil {
		appendWarning(warnings, "complexity_parse_failed", err.Error())
		return nil
	}

	boundary := params["boundary"]
	if boundary == "" {
		appendWarning(warnings, "complexity_parse_failed", "multipart boundary is missing")
		return nil
	}

	reader := multipart.NewReader(bytes.NewReader(sample.observed), boundary)
	partCount := 0
	nameCounts := make(map[string]int)
	maxValuesPerKey := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			appendWarning(warnings, "complexity_parse_failed", err.Error())
			break
		}

		partCount++
		if name := part.FormName(); name != "" {
			nameCounts[name]++
			if nameCounts[name] > maxValuesPerKey {
				maxValuesPerKey = nameCounts[name]
			}
		}
		_ = part.Close()
	}

	repeatedKeys := 0
	for _, count := range nameCounts {
		if count > 1 {
			repeatedKeys++
		}
	}

	factors := []ScoreFactor{
		{Name: "parts", Value: minInt(partCount/5, 20)},
		{Name: "repeated_keys", Value: repeatedKeys},
		{Name: "max_values_per_key", Value: minInt(maxValuesPerKey, 20)},
	}

	objectCount := 0
	if partCount > 0 {
		objectCount = 1
	}

	return &ComplexityResult{
		ContentType:    "multipart/form-data",
		Depth:          1,
		FieldCount:     partCount,
		ObjectCount:    objectCount,
		ArrayCount:     repeatedKeys,
		MaxArrayLength: maxValuesPerKey,
		Score:          sumScoreFactors(factors),
		ScoreFactors:   factors,
	}
}

func sumScoreFactors(factors []ScoreFactor) int {
	score := 0
	for _, factor := range factors {
		score += factor.Value
	}
	return score
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
