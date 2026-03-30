package webprofiler

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

func analyzeCharset(sample bodySample, cfg CharsetConfig, warnings *[]Warning) *CharsetResult {
	if !sample.analyzed || len(sample.sample) == 0 || !isTextContentType(sample.contentType) {
		return nil
	}

	if !sample.isDecodedForStructuredAnalysis() {
		return nil
	}

	data := sample.sample
	if cfg.MaxAnalyzeBytes > 0 && len(data) > cfg.MaxAnalyzeBytes {
		data = data[:cfg.MaxAnalyzeBytes]
		data = trimIncompleteUTF8Suffix(data)
	}
	analyzedData := data

	totalChars := 0
	asciiAlpha := 0
	digits := 0
	whitespace := 0
	symbols := 0
	control := 0
	nonASCII := 0
	emoji := 0
	invisible := 0
	confusable := 0
	zeroWidthFound := false
	scriptCounts := make(map[string]int)

	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			control++
			totalChars++
			data = data[size:]
			continue
		}

		totalChars++
		if r <= unicode.MaxASCII {
			switch {
			case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
				asciiAlpha++
			case '0' <= r && r <= '9':
				digits++
			case unicode.IsSpace(r):
				whitespace++
			case unicode.IsControl(r):
				control++
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				symbols++
			}
		} else {
			nonASCII++
			switch {
			case unicode.IsSpace(r):
				whitespace++
			case unicode.IsControl(r):
				control++
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				symbols++
			}
		}

		if isZeroWidthRune(r) {
			zeroWidthFound = true
		}
		if isEmojiRune(r) {
			emoji++
		}
		if isInvisibleRune(r) {
			invisible++
		}
		if cfg.EnableConfusableDetection && confusableSkeleton(r) != "" {
			confusable++
		}
		if cfg.EnableUnicodeScripts {
			if script := majorScript(r); script != "" {
				scriptCounts[script]++
			}
		}

		data = data[size:]
	}

	if totalChars == 0 {
		return nil
	}

	result := &CharsetResult{
		TotalChars:          totalChars,
		ASCIIAlphaRatio:     ratio(asciiAlpha, totalChars),
		DigitRatio:          ratio(digits, totalChars),
		WhitespaceRatio:     ratio(whitespace, totalChars),
		SymbolRatio:         ratio(symbols, totalChars),
		ControlCharRatio:    ratio(control, totalChars),
		NonASCIIRatio:       ratio(nonASCII, totalChars),
		EmojiRatio:          ratio(emoji, totalChars),
		InvisibleCharRatio:  ratio(invisible, totalChars),
		ConfusableCount:     confusable,
		UnicodeScriptCounts: make(map[string]int, len(scriptCounts)),
	}
	for script, count := range scriptCounts {
		result.UnicodeScriptCounts[script] = count
	}
	if cfg.EnableFormatSpecificMetrics {
		formatMetrics, err := analyzeFormatTextMetrics(sample.contentType, analyzedData)
		result.FormatMetrics = formatMetrics
		if err != nil {
			code := "charset_format_metrics_failed"
			if formatMetrics != nil {
				code = "charset_format_metrics_partial"
			}
			appendWarning(warnings, code, err.Error())
		}
	}

	if cfg.EnableSuspiciousPattern {
		if !utf8.Valid(analyzedData) {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "invalid_utf8")
		}
		if control > 0 {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "control_chars")
		}
		if zeroWidthFound {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "zero_width_chars")
		}
		if cfg.EnableUnicodeScripts && len(scriptCounts) > 1 {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "mixed_unicode_scripts")
		}
		if cfg.EnableConfusableDetection && shouldFlagConfusable(scriptCounts, confusable) {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "confusable_homoglyphs")
		}
	}

	return result
}

func trimIncompleteUTF8Suffix(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	start := len(data) - 1
	for start > 0 && data[start]&0xC0 == 0x80 {
		start--
	}
	if utf8.FullRune(data[start:]) {
		return data
	}
	return data[:start]
}

func isTextContentType(contentType string) bool {
	return matchContentTypePattern(contentType, "text/*") ||
		matchContentTypePattern(contentType, "application/json") ||
		matchContentTypePattern(contentType, "application/*+json") ||
		matchContentTypePattern(contentType, "application/x-www-form-urlencoded") ||
		matchContentTypePattern(contentType, "text/xml") ||
		matchContentTypePattern(contentType, "application/xml") ||
		matchContentTypePattern(contentType, "application/*+xml")
}

func isZeroWidthRune(r rune) bool {
	switch r {
	case '\u200b', '\u200c', '\u200d', '\ufeff':
		return true
	default:
		return false
	}
}

func isInvisibleRune(r rune) bool {
	if isZeroWidthRune(r) {
		return true
	}
	if unicode.IsControl(r) && !unicode.IsSpace(r) {
		return true
	}
	return unicode.In(r, unicode.Cf)
}

func isEmojiRune(r rune) bool {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF:
		return true
	case r >= 0x2600 && r <= 0x27BF:
		return true
	default:
		return false
	}
}

func majorScript(r rune) string {
	switch {
	case unicode.Is(unicode.Latin, r):
		return "latin"
	case unicode.Is(unicode.Han, r):
		return "han"
	case unicode.Is(unicode.Hiragana, r):
		return "hiragana"
	case unicode.Is(unicode.Katakana, r):
		return "katakana"
	case unicode.Is(unicode.Hangul, r):
		return "hangul"
	case unicode.Is(unicode.Cyrillic, r):
		return "cyrillic"
	case unicode.Is(unicode.Arabic, r):
		return "arabic"
	default:
		return ""
	}
}

func shouldFlagConfusable(scriptCounts map[string]int, confusableCount int) bool {
	if confusableCount == 0 {
		return false
	}
	if len(scriptCounts) == 0 {
		return true
	}
	if scriptCounts["latin"] > 0 {
		return true
	}
	return len(scriptCounts) > 1
}

func confusableSkeleton(r rune) string {
	switch r {
	case '\u0391', '\u0410', '\u0430':
		return "a"
	case '\u0392', '\u0412':
		return "b"
	case '\u03F9', '\u0421', '\u0441':
		return "c"
	case '\u0395', '\u0415', '\u0435':
		return "e"
	case '\u0397', '\u041D':
		return "h"
	case '\u0399', '\u0406', '\u0456':
		return "i"
	case '\u039A', '\u041A', '\u043A':
		return "k"
	case '\u039C', '\u041C', '\u043C':
		return "m"
	case '\u039D':
		return "n"
	case '\u039F', '\u041E', '\u043E':
		return "o"
	case '\u03A1', '\u0420', '\u0440':
		return "p"
	case '\u03A4', '\u0422', '\u0442':
		return "t"
	case '\u03A5', '\u0423', '\u0443':
		return "y"
	case '\u03A7', '\u0425', '\u0445':
		return "x"
	case '\u0408', '\u0458':
		return "j"
	default:
		return ""
	}
}

type jsonFrame struct {
	kind      byte
	expectKey bool
}

func analyzeFormatTextMetrics(contentType string, data []byte) (*FormatTextMetrics, error) {
	switch {
	case matchContentTypePattern(contentType, "application/json"),
		matchContentTypePattern(contentType, "application/*+json"):
		return analyzeJSONTextMetrics(data)
	case contentType == "application/x-www-form-urlencoded":
		return analyzeFormTextMetrics(data)
	case matchContentTypePattern(contentType, "application/xml"),
		matchContentTypePattern(contentType, "application/*+xml"),
		matchContentTypePattern(contentType, "text/xml"):
		return analyzeXMLTextMetrics(data)
	default:
		return nil, nil
	}
}

func analyzeJSONTextMetrics(data []byte) (*FormatTextMetrics, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	metrics := &FormatTextMetrics{Format: "json"}
	frames := make([]jsonFrame, 0, 8)
	topLevelValueComplete := false

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if metrics.TokenCount == 0 {
				return nil, err
			}
			return metrics, err
		}
		if topLevelValueComplete {
			return metrics, errors.New("unexpected trailing data after JSON payload")
		}

		metrics.TokenCount++
		switch typed := token.(type) {
		case json.Delim:
			switch typed {
			case '{':
				frames = append(frames, jsonFrame{kind: '{', expectKey: true})
			case '[':
				frames = append(frames, jsonFrame{kind: '['})
			case '}', ']':
				if len(frames) > 0 {
					frames = frames[:len(frames)-1]
				}
				markJSONValueConsumed(frames)
			}
		case string:
			updateMaxTokenLength(metrics, len(typed))
			if isJSONObjectKey(frames) {
				metrics.KeyCount++
				frames[len(frames)-1].expectKey = false
				continue
			}
			metrics.ValueCount++
			metrics.StringValueCount++
			markJSONValueConsumed(frames)
		case json.Number:
			updateMaxTokenLength(metrics, len(typed.String()))
			metrics.ValueCount++
			metrics.NumberValueCount++
			markJSONValueConsumed(frames)
		case bool:
			if typed {
				updateMaxTokenLength(metrics, len("true"))
			} else {
				updateMaxTokenLength(metrics, len("false"))
			}
			metrics.ValueCount++
			markJSONValueConsumed(frames)
		case nil:
			updateMaxTokenLength(metrics, len("null"))
			metrics.ValueCount++
			markJSONValueConsumed(frames)
		}

		if len(frames) == 0 && metrics.TokenCount > 0 {
			topLevelValueComplete = true
		}
	}

	if len(frames) > 0 {
		return metrics, io.ErrUnexpectedEOF
	}

	return metrics, nil
}

func isJSONObjectKey(frames []jsonFrame) bool {
	if len(frames) == 0 {
		return false
	}
	top := frames[len(frames)-1]
	return top.kind == '{' && top.expectKey
}

func markJSONValueConsumed(frames []jsonFrame) {
	if len(frames) == 0 {
		return
	}
	top := &frames[len(frames)-1]
	if top.kind == '{' && !top.expectKey {
		top.expectKey = true
	}
}

func analyzeFormTextMetrics(data []byte) (*FormatTextMetrics, error) {
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, err
	}

	metrics := &FormatTextMetrics{Format: "form"}
	metrics.KeyCount = len(values)
	for key, values := range values {
		updateMaxTokenLength(metrics, len(key))
		metrics.TokenCount++
		for _, value := range values {
			metrics.ValueCount++
			metrics.StringValueCount++
			metrics.TokenCount++
			updateMaxTokenLength(metrics, len(value))
		}
		if len(values) > 1 {
			metrics.RepeatedKeyCount++
		}
	}

	return metrics, nil
}

func analyzeXMLTextMetrics(data []byte) (*FormatTextMetrics, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	metrics := &FormatTextMetrics{Format: "xml"}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if metrics.TokenCount == 0 {
				return nil, err
			}
			return metrics, err
		}

		switch typed := token.(type) {
		case xml.StartElement:
			metrics.TagCount++
			metrics.TokenCount++
			updateMaxTokenLength(metrics, len(typed.Name.Local))
			for _, attr := range typed.Attr {
				metrics.AttributeCount++
				updateMaxTokenLength(metrics, len(attr.Name.Local))
				updateMaxTokenLength(metrics, len(attr.Value))
			}
		case xml.CharData:
			text := strings.TrimSpace(string(typed))
			if text == "" {
				continue
			}
			metrics.TextNodeCount++
			metrics.ValueCount++
			metrics.StringValueCount++
			metrics.TokenCount++
			updateMaxTokenLength(metrics, len(text))
		}
	}

	return metrics, nil
}

func updateMaxTokenLength(metrics *FormatTextMetrics, length int) {
	if metrics == nil {
		return
	}
	if length > metrics.MaxTokenLength {
		metrics.MaxTokenLength = length
	}
}

func ratio(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}
