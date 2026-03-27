package webprofiler

import "context"

type contextKey struct{}

func FromContext(ctx context.Context) (*Profile, bool) {
	if ctx == nil {
		return nil, false
	}

	profile, ok := ctx.Value(contextKey{}).(*Profile)
	if !ok || profile == nil {
		return nil, false
	}

	return profile, true
}

func withProfile(ctx context.Context, profile *Profile) context.Context {
	return context.WithValue(ctx, contextKey{}, profile)
}
