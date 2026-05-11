package pq

import (
	"testing"
)

func TestEnvTruthyValuesYieldStrict(t *testing.T) {
	cases := []string{"1", "true", "TRUE", "True", "on", "ON", "yes", "Y", "  1  "}
	for _, v := range cases {
		t.Setenv(EnvVar, v)
		if got := ProfileFromEnv(); got != Strict() {
			t.Errorf("env=%q expected Strict; got %+v", v, got)
		}
	}
}

func TestEnvFalsyValuesYieldPermissive(t *testing.T) {
	cases := []string{"", "0", "false", "no", "off", "anything", "2"}
	for _, v := range cases {
		t.Setenv(EnvVar, v)
		if got := ProfileFromEnv(); got != Permissive() {
			t.Errorf("env=%q expected Permissive; got %+v", v, got)
		}
	}
}
