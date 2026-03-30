package model

import (
	"time"

	"github.com/GoFurry/web-profiler/internal/policy"
)

type SampleStrategy = policy.SampleStrategy

type Profile struct {
	Meta        MetaInfo
	Entropy     *EntropyResult
	Fingerprint *FingerprintResult
	Complexity  *ComplexityResult
	Charset     *CharsetResult
	Warnings    []Warning
}

type MetaInfo struct {
	Method              string
	Path                string
	ContentType         string
	ContentLength       int64
	ObservedBytes       int64
	HeaderCount         int
	HeaderBytes         int
	Sampled             bool
	SampleBytes         int
	Truncated           bool
	FingerprintDuration time.Duration
	BodyCaptureDuration time.Duration
	EntropyDuration     time.Duration
	ComplexityDuration  time.Duration
	CharsetDuration     time.Duration
	AnalysisDuration    time.Duration
}

type EntropyResult struct {
	Value                 float64
	NormalizedValue       float64
	SampledBytes          int
	TotalObservedBytes    int64
	UniqueByteCount       int
	RepetitionRatio       float64
	CompressionRatio      float64
	ApproxCompressibility float64
	SampleStrategy        SampleStrategy
}

type FingerprintResult struct {
	Fields        map[string]string
	SourceFlags   []string
	Hash          string
	WeakHash      string
	StrongHash    string
	HashAlgorithm string
	HashVersion   string
}

type ComplexityResult struct {
	ContentType                string
	Depth                      int
	FieldCount                 int
	ObjectCount                int
	ArrayCount                 int
	ScalarCount                int
	NullCount                  int
	StringCount                int
	UniqueKeyCount             int
	MaxArrayLength             int
	MaxObjectFields            int
	MaxKeyLength               int
	MaxStringLength            int
	MaxValueLength             int
	AverageKeyLength           float64
	AverageValueLength         float64
	MultipartFileCount         int
	MultipartFieldCount        int
	MultipartFileExtensions    map[string]int
	MultipartFileContentTypes  map[string]int
	MultipartMaxFileNameLength int
	Score                      int
	ScoreFactors               []ScoreFactor
}

type ScoreFactor struct {
	Name  string
	Value int
}

type FormatTextMetrics struct {
	Format           string
	TokenCount       int
	KeyCount         int
	ValueCount       int
	StringValueCount int
	NumberValueCount int
	RepeatedKeyCount int
	TagCount         int
	AttributeCount   int
	TextNodeCount    int
	MaxTokenLength   int
}

type CharsetResult struct {
	TotalChars          int
	ASCIIAlphaRatio     float64
	DigitRatio          float64
	WhitespaceRatio     float64
	SymbolRatio         float64
	ControlCharRatio    float64
	NonASCIIRatio       float64
	EmojiRatio          float64
	InvisibleCharRatio  float64
	ConfusableCount     int
	UnicodeScriptCounts map[string]int
	FormatMetrics       *FormatTextMetrics
	SuspiciousFlags     []string
}

type Warning struct {
	Code    string
	Message string
}
