package core

import (
	"github.com/GoFurry/web-profiler/internal/model"
	"github.com/GoFurry/web-profiler/internal/policy"
)

type (
	SampleStrategy    = policy.SampleStrategy
	Config            = policy.Config
	BodyConfig        = policy.BodyConfig
	FingerprintConfig = policy.FingerprintConfig
	ComplexityConfig  = policy.ComplexityConfig
	CharsetConfig     = policy.CharsetConfig

	Profile           = model.Profile
	MetaInfo          = model.MetaInfo
	EntropyResult     = model.EntropyResult
	FingerprintResult = model.FingerprintResult
	ComplexityResult  = model.ComplexityResult
	ScoreFactor       = model.ScoreFactor
	FormatTextMetrics = model.FormatTextMetrics
	CharsetResult     = model.CharsetResult
	Warning           = model.Warning
)

const (
	SampleStrategyHead     = policy.SampleStrategyHead
	SampleStrategyTail     = policy.SampleStrategyTail
	SampleStrategyHeadTail = policy.SampleStrategyHeadTail

	defaultReadChunkSize = 8 << 10
)

func DefaultConfig() Config {
	return policy.DefaultConfig()
}

func normalizeConfig(cfg Config) Config {
	return policy.NormalizeConfig(cfg)
}
