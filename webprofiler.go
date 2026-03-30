package webprofiler

import (
	"context"
	"net/http"

	"github.com/GoFurry/web-profiler/internal/core"
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
)

func DefaultConfig() Config {
	return policy.DefaultConfig()
}

func Middleware(cfg Config) func(http.Handler) http.Handler {
	return core.Middleware(cfg)
}

func Wrap(next http.Handler, cfg Config) http.Handler {
	return core.Wrap(next, cfg)
}

func FromContext(ctx context.Context) (*Profile, bool) {
	return core.FromContext(ctx)
}
