package pq

import "context"

// ctxKey is unexported so external packages cannot collide on it.
type ctxKey struct{}

// WithProfile returns a child context that carries p as its active
// profile. Subsequent calls to [Refuse] and [FromContext] on the
// returned context observe p.
func WithProfile(parent context.Context, p Profile) context.Context {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithValue(parent, ctxKey{}, p)
}

// FromContext returns the profile bound to ctx. When no profile is
// bound, it returns [Permissive] — the failure-open default for code
// paths that have not yet been audited for strict enforcement.
//
// Mainnet binaries bind a profile at startup so this default is never
// observed in production; in development and tests the default keeps
// the gate transparent.
func FromContext(ctx context.Context) Profile {
	if ctx == nil {
		return Permissive()
	}
	if v, ok := ctx.Value(ctxKey{}).(Profile); ok {
		return v
	}
	return Permissive()
}
