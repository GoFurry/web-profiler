package webprofiler

import (
	"unicode"
	"unicode/utf8"
)

func analyzeCharset(sample bodySample, cfg CharsetConfig) *CharsetResult {
	if !sample.analyzed || len(sample.sample) == 0 || !isTextContentType(sample.contentType) {
		return nil
	}

	data := sample.sample
	if cfg.MaxAnalyzeBytes > 0 && len(data) > cfg.MaxAnalyzeBytes {
		data = data[:cfg.MaxAnalyzeBytes]
	}

	totalChars := 0
	asciiAlpha := 0
	digits := 0
	whitespace := 0
	symbols := 0
	control := 0
	nonASCII := 0
	zeroWidthFound := false
	scripts := make(map[string]struct{})

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
		if cfg.EnableUnicodeScripts {
			if script := majorScript(r); script != "" {
				scripts[script] = struct{}{}
			}
		}

		data = data[size:]
	}

	if totalChars == 0 {
		return nil
	}

	result := &CharsetResult{
		TotalChars:       totalChars,
		ASCIIAlphaRatio:  ratio(asciiAlpha, totalChars),
		DigitRatio:       ratio(digits, totalChars),
		WhitespaceRatio:  ratio(whitespace, totalChars),
		SymbolRatio:      ratio(symbols, totalChars),
		ControlCharRatio: ratio(control, totalChars),
		NonASCIIRatio:    ratio(nonASCII, totalChars),
	}

	if cfg.EnableSuspiciousPattern {
		if !utf8.Valid(sample.sample) {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "invalid_utf8")
		}
		if control > 0 {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "control_chars")
		}
		if zeroWidthFound {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "zero_width_chars")
		}
		if cfg.EnableUnicodeScripts && len(scripts) > 1 {
			result.SuspiciousFlags = append(result.SuspiciousFlags, "mixed_unicode_scripts")
		}
	}

	return result
}

func isTextContentType(contentType string) bool {
	return matchContentTypePattern(contentType, "text/*") ||
		matchContentTypePattern(contentType, "application/json") ||
		matchContentTypePattern(contentType, "application/*+json") ||
		matchContentTypePattern(contentType, "application/x-www-form-urlencoded") ||
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

func ratio(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}
