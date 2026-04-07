package core

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
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
	seenKeys        map[string]struct{}
	maxArrayLength  int
	maxObjectFields int
	maxKeyLength    int
	maxStringLength int
}

func analyzeComplexity(sample bodySample, cfg ComplexityConfig, warnings *[]Warning) *ComplexityResult {
	if !sample.analyzed || len(sample.observed) == 0 {
		return nil
	}

	if !sample.isDecodedForStructuredAnalysis() {
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
	case matchContentTypePattern(sample.contentType, "application/xml"),
		matchContentTypePattern(sample.contentType, "application/*+xml"),
		matchContentTypePattern(sample.contentType, "text/xml"):
		return analyzeXMLComplexity(sample, cfg, warnings)
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
	if err := ensureSingleJSONPayload(decoder); err != nil {
		appendWarning(warnings, "complexity_parse_failed", err.Error())
		return nil
	}

	stats := jsonComplexityStats{
		seenKeys: make(map[string]struct{}),
	}
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
		if len(typed) > stats.maxObjectFields {
			stats.maxObjectFields = len(typed)
		}
		if stats.fieldCount > cfg.MaxFields {
			return errComplexityFieldExceeded
		}
		for key, child := range typed {
			if _, ok := stats.seenKeys[key]; !ok {
				stats.seenKeys[key] = struct{}{}
				stats.uniqueKeyCount++
			}
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

func ensureSingleJSONPayload(decoder *json.Decoder) error {
	if decoder == nil {
		return nil
	}

	_, err := decoder.Token()
	switch err {
	case nil:
		return errors.New("unexpected trailing data after JSON payload")
	case io.EOF:
		return nil
	default:
		return err
	}
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

func analyzeXMLComplexity(sample bodySample, cfg ComplexityConfig, warnings *[]Warning) *ComplexityResult {
	decoder := xml.NewDecoder(bytes.NewReader(sample.observed))

	depth := 0
	maxDepth := 0
	elementCount := 0
	attributeCount := 0
	textNodeCount := 0
	maxAttributes := 0
	maxNameLength := 0
	maxTextLength := 0
	maxAttributeValueLength := 0
	totalNameLength := 0
	totalValueLength := 0
	valueCount := 0
	nameCount := 0
	uniqueNames := make(map[string]struct{})

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			appendWarning(warnings, "complexity_parse_failed", err.Error())
			if elementCount == 0 && attributeCount == 0 && textNodeCount == 0 {
				return nil
			}
			break
		}

		switch typed := token.(type) {
		case xml.StartElement:
			depth++
			if depth > cfg.MaxJSONDepth {
				appendWarning(warnings, "complexity_limit_exceeded", errComplexityDepthExceeded.Error())
				depth--
				return buildXMLComplexityResult(sample.contentType, maxDepth, elementCount, attributeCount, textNodeCount, len(uniqueNames), maxAttributes, maxNameLength, maxTextLength, maxAttributeValueLength, totalNameLength, totalValueLength, nameCount, valueCount)
			}
			if depth > maxDepth {
				maxDepth = depth
			}

			elementCount++
			if elementCount+attributeCount > cfg.MaxFields {
				appendWarning(warnings, "complexity_limit_exceeded", errComplexityFieldExceeded.Error())
				return buildXMLComplexityResult(sample.contentType, maxDepth, elementCount, attributeCount, textNodeCount, len(uniqueNames), maxAttributes, maxNameLength, maxTextLength, maxAttributeValueLength, totalNameLength, totalValueLength, nameCount, valueCount)
			}

			elementNameLength := len(typed.Name.Local)
			totalNameLength += elementNameLength
			nameCount++
			if elementNameLength > maxNameLength {
				maxNameLength = elementNameLength
			}
			if typed.Name.Local != "" {
				uniqueNames[typed.Name.Local] = struct{}{}
			}

			if len(typed.Attr) > maxAttributes {
				maxAttributes = len(typed.Attr)
			}
			for _, attr := range typed.Attr {
				attributeCount++
				if elementCount+attributeCount > cfg.MaxFields {
					appendWarning(warnings, "complexity_limit_exceeded", errComplexityFieldExceeded.Error())
					return buildXMLComplexityResult(sample.contentType, maxDepth, elementCount, attributeCount, textNodeCount, len(uniqueNames), maxAttributes, maxNameLength, maxTextLength, maxAttributeValueLength, totalNameLength, totalValueLength, nameCount, valueCount)
				}

				nameLength := len(attr.Name.Local)
				totalNameLength += nameLength
				nameCount++
				if nameLength > maxNameLength {
					maxNameLength = nameLength
				}
				if attr.Name.Local != "" {
					uniqueNames[attr.Name.Local] = struct{}{}
				}

				valueLength := len(attr.Value)
				totalValueLength += valueLength
				valueCount++
				if valueLength > maxAttributeValueLength {
					maxAttributeValueLength = valueLength
				}
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		case xml.CharData:
			text := strings.TrimSpace(string(typed))
			if text == "" {
				continue
			}
			textNodeCount++
			valueCount++
			textLength := len(text)
			totalValueLength += textLength
			if textLength > maxTextLength {
				maxTextLength = textLength
			}
		}
	}

	return buildXMLComplexityResult(sample.contentType, maxDepth, elementCount, attributeCount, textNodeCount, len(uniqueNames), maxAttributes, maxNameLength, maxTextLength, maxAttributeValueLength, totalNameLength, totalValueLength, nameCount, valueCount)
}

func buildXMLComplexityResult(contentType string, depth, elementCount, attributeCount, textNodeCount, uniqueKeyCount, maxAttributes, maxNameLength, maxTextLength, maxAttributeValueLength, totalNameLength, totalValueLength, nameCount, valueCount int) *ComplexityResult {
	factors := []ScoreFactor{
		{Name: "depth", Value: depth},
		{Name: "fields", Value: minInt((elementCount+attributeCount)/10, 20)},
		{Name: "text_nodes", Value: minInt(textNodeCount, 20)},
	}

	averageKeyLength := 0.0
	if nameCount > 0 {
		averageKeyLength = float64(totalNameLength) / float64(nameCount)
	}

	averageValueLength := 0.0
	if valueCount > 0 {
		averageValueLength = float64(totalValueLength) / float64(valueCount)
	}

	return &ComplexityResult{
		ContentType:        contentType,
		Depth:              depth,
		FieldCount:         elementCount + attributeCount,
		ObjectCount:        elementCount,
		ScalarCount:        textNodeCount,
		StringCount:        textNodeCount,
		UniqueKeyCount:     uniqueKeyCount,
		MaxObjectFields:    maxAttributes,
		MaxKeyLength:       maxNameLength,
		MaxStringLength:    maxTextLength,
		MaxValueLength:     maxAttributeValueLength,
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
