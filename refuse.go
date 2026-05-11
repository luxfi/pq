package annulus

import (
	"context"
	"errors"
	"fmt"
)

// Violation is returned when an operation is inadmissible under the
// active profile. It records the op that was rejected and the hash of
// the profile that rejected it.
type Violation struct {
	Op      Op
	Profile [32]byte
}

// Error implements the error interface.
func (v *Violation) Error() string {
	return fmt.Sprintf("annulus: %s forbidden under profile %x", v.Op, v.Profile[:8])
}

// ErrUnknownOp is returned when [Refuse] is invoked with an [Op] that
// the package does not recognize. Callers must ship a recognized op;
// the failure-closed default is to refuse.
var ErrUnknownOp = errors.New("annulus: unknown op")

// Refuse reports whether the profile bound to ctx admits op.
// A nil return means the op is allowed. A non-nil error means the op
// must not execute.
//
// When ctx carries no profile, the [Permissive] profile is used. When
// ctx is nil, Refuse panics; this signals a programmer error.
//
// Refuse is the single profile gate. Each constrained operation calls
// it once at the top of its entry point and otherwise proceeds in its
// own lane.
func Refuse(ctx context.Context, op Op) error {
	if ctx == nil {
		panic("annulus.Refuse: nil context")
	}
	p := FromContext(ctx)
	return RefuseUnder(p, op)
}

// RefuseUnder is the context-free variant of [Refuse]. It is the
// canonical entry point for unit tests and for subsystems that resolve
// the active profile through their own indirection.
func RefuseUnder(p Profile, op Op) error {
	cat := CategoryOf(op)
	if cat == CatUnknown {
		return fmt.Errorf("%w: %s", ErrUnknownOp, op)
	}
	if !p.Forbids(cat) {
		return nil
	}
	h := p.Hash()
	return &Violation{Op: op, Profile: h}
}

// MustRefuse is the panicking variant of [Refuse]; suitable only for
// initialisation paths where a profile violation indicates a build
// configuration error rather than a runtime input.
func MustRefuse(ctx context.Context, op Op) {
	if err := Refuse(ctx, op); err != nil {
		panic(err)
	}
}
