package pq

import (
	"os"
	"strings"
)

// EnvVar is the single environment variable that selects the active
// profile at startup. Production binaries read it once in main and
// install the result via [SetActive].
const EnvVar = "QUASAR_STRICT_PQ"

// truthy enumerates the values [FromEnv] accepts as "set".
var truthy = map[string]bool{
	"1":    true,
	"true": true,
	"on":   true,
	"yes":  true,
	"y":    true,
}

// FromEnv returns [Strict] when [EnvVar] is set to a truthy value
// (case-insensitive) and [Permissive] otherwise.
func FromEnv() *Profile {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvVar)))
	if truthy[v] {
		return Strict()
	}
	return Permissive()
}
