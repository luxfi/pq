package pq

import (
	"context"
	"testing"
)

func TestWithProfileBindsValue(t *testing.T) {
	ctx := WithProfile(context.Background(), Strict())
	if got := FromContext(ctx); got != Strict() {
		t.Errorf("bound profile not retrieved\n got %+v\nwant %+v", got, Strict())
	}
}

func TestFromContextDefaultsPermissive(t *testing.T) {
	if got := FromContext(context.Background()); got != Permissive() {
		t.Error("unbound context must yield Permissive")
	}
}

func TestFromContextNilSafe(t *testing.T) {
	if got := FromContext(nil); got != Permissive() { //nolint:staticcheck
		t.Error("nil context must yield Permissive")
	}
}

func TestWithProfileNilParentSafe(t *testing.T) {
	ctx := WithProfile(nil, Strict()) //nolint:staticcheck
	if got := FromContext(ctx); got != Strict() {
		t.Error("nil parent must still yield bound profile")
	}
}

func TestContextOverridesParent(t *testing.T) {
	parent := WithProfile(context.Background(), Permissive())
	child := WithProfile(parent, Strict())
	if FromContext(child) != Strict() {
		t.Error("child profile must override parent")
	}
	if FromContext(parent) != Permissive() {
		t.Error("parent must remain unchanged")
	}
}
