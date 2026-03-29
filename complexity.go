package webprofiler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"path/filepath"
	"strings"
)

var (
	errComplexityDepthExceeded = errors.New("maximum JSON depth exceeded")
	errComplexityFieldExceeded = errors.New("maximum field count exceeded")
)

type jsonComplexityStats struct {
	depth           int
	fieldCount      int
	objectCount     int
	arrayCount      int
	scalarCount     int
	nullCount       int
	stringCount     int
	uniqueKeyCount  int
	maxArrayLength  int
	maxObjectFields int
	maxKeyLength    int
	maxStringLength int
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
		ContentType:     sample.contentType,
		Depth:           stats.depth,
		FieldCount:      stats.fieldCount,
		ObjectCount:     stats.objectCount,
		ArrayCount:      stats.arrayCount,
		ScalarCount:     stats.scalarCount,
		NullCount:       stats.nullCount,
		StringCount:     stats.stringCount,
		UniqueKeyCount:  stats.uniqueKeyCount,
		MaxArrayLength:  stats.maxArrayLength,
		MaxObjectFields: stats.maxObjectFields,
		MaxKeyLength:    stats.maxKeyLength,
		MaxStringLength: stats.maxStringLength,
		Score:           sumScoreFactors(factors),
		ScoreFactors:    factors,
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
		stats.uniqueKeyCount += len(typed)
		if len(typed) > stats.maxObjectFields {
			stats.maxObjectFields = len(typed)
		}
		if stats.fieldCount > cfg.MaxFields {
			return errComplexityFieldExceeded
		}
		for key, child := range typed {
			if len(key) > stats.maxKeyLength {
				stats.maxKeyLength = len(key)
			}
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
	case string:
		stats.scalarCount++
		stats.stringCount++
		if len(typed) > stats.maxStringLength {
			stats.maxStringLength = len(typed)
		}
	case nil:
		stats.scalarCount++
		stats.nullCount++
	default:
		stats.scalarCount++
	}

	return nil
}

func analyzeFormComplexity(data []byte) *ComplexityResult {
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return nil
	}

	fieldCount := 0
	uniqueKeyCount := len(values)
	repeatedKeys := 0
	maxArrayLength := 0
	maxKeyLength := 0
	maxValueLength := 0
	totalKeyLength := 0
	totalValueLength := 0
	for _, values := range values {
		fieldCount += len(values)
		if len(values) > 1 {
			repeatedKeys++
		}
		if len(values) > maxArrayLength {
			maxArrayLength = len(values)
		}
	}
	for key, values := range values {
		keyLength := len(key)
		totalKeyLength += keyLength
		if keyLength > maxKeyLength {
			maxKeyLength = keyLength
		}
		for _, value := range values {
			valueLength := len(value)
			totalValueLength += valueLength
			if valueLength > maxValueLength {
				maxValueLength = valueLength
			}
		}
	}

	averageKeyLength := 0.0
	if uniqueKeyCount > 0 {
		averageKeyLength = float64(totalKeyLength) / float64(uniqueKeyCount)
	}

	averageValueLength := 0.0
	if fieldCount > 0 {
		averageValueLength = float64(totalValueLength) / float64(fieldCount)
	}

	factors := []ScoreFactor{
		{Name: "fields", Value: minInt(fieldCount/10, 20)},
		{Name: "repeated_keys", Value: repeatedKeys},
		{Name: "max_values_per_key", Value: minInt(maxArrayLength, 20)},
	}

	return &ComplexityResult{
		ContentType:        "application/x-www-form-urlencoded",
		Depth:              1,
		FieldCount:         fieldCount,
		ObjectCount:        1,
		ArrayCount:         repeatedKeys,
		ScalarCount:        fieldCount,
		StringCount:        fieldCount,
		UniqueKeyCount:     uniqueKeyCount,
		MaxArrayLength:     maxArrayLength,
		MaxObjectFields:    uniqueKeyCount,
		MaxKeyLength:       maxKeyLength,
		MaxValueLength:     maxValueLength,
		AverageKeyLength:   averageKeyLength,
		AverageValueLength: averageValueLength,
		Score:              sumScoreFactors(factors),
		ScoreFactors:       factors,
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
	fileCount := 0
	fieldCount := 0
	fileExtensions := make(map[string]int)
	fileContentTypes := make(map[string]int)
	maxFileNameLength := 0

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
		if fileName := part.FileName(); fileName != "" {
			fileCount++
			if len(fileName) > maxFileNameLength {
				maxFileNameLength = len(fileName)
			}
			if ext := normalizeFileExtension(fileName); ext != "" {
				fileExtensions[ext]++
			}
			if contentType := normalizedContentType(part.Header.Get("Content-Type")); contentType != "" {
				fileContentTypes[contentType]++
			}
		} else {
			fieldCount++
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
		ContentType:                "multipart/form-data",
		Depth:                      1,
		FieldCount:                 partCount,
		ObjectCount:                objectCount,
		ArrayCount:                 repeatedKeys,
		ScalarCount:                fieldCount,
		StringCount:                fieldCount,
		UniqueKeyCount:             len(nameCounts),
		MaxArrayLength:             maxValuesPerKey,
		MaxObjectFields:            len(nameCounts),
		MultipartFileCount:         fileCount,
		MultipartFieldCount:        fieldCount,
		MultipartFileExtensions:    fileExtensions,
		MultipartFileContentTypes:  fileContentTypes,
		MultipartMaxFileNameLength: maxFileNameLength,
		Score:                      sumScoreFactors(factors),
		ScoreFactors:               factors,
	}
}

func normalizeFileExtension(fileName string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(fileName), "."))
	return strings.TrimSpace(ext)
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
