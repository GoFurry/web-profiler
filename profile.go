package webprofiler

import "time"

type Profile struct {
	Meta        MetaInfo
	Entropy     *EntropyResult
	Fingerprint *FingerprintResult
	Complexity  *ComplexityResult
	Charset     *CharsetResult
	Warnings    []Warning
}

type MetaInfo struct {
	Method           string
	Path             string
	ContentType      string
	ContentLength    int64
	Sampled          bool
	SampleBytes      int
	Truncated        bool
	AnalysisDuration time.Duration
}

type EntropyResult struct {
	Value              float64
	SampledBytes       int
	TotalObservedBytes int64
	SampleStrategy     SampleStrategy
}

type FingerprintResult struct {
	Fields        map[string]string
	Hash          string
	HashAlgorithm string
	HashVersion   string
}

type ComplexityResult struct {
	ContentType    string
	Depth          int
	FieldCount     int
	ObjectCount    int
	ArrayCount     int
	MaxArrayLength int
	Score          int
	ScoreFactors   []ScoreFactor
}

type ScoreFactor struct {
	Name  string
	Value int
}

type CharsetResult struct {
	TotalChars       int
	ASCIIAlphaRatio  float64
	DigitRatio       float64
	WhitespaceRatio  float64
	SymbolRatio      float64
	ControlCharRatio float64
	NonASCIIRatio    float64
	SuspiciousFlags  []string
}

type Warning struct {
	Code    string
	Message string
}
