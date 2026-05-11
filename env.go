package annulus

import (
	"os"
	"strings"
)

// EnvVar is the name of the single environment variable that selects
// the active profile at startup. Production binaries read it once in
// main and bind the resulting profile to their root context.
const EnvVar = "QUASAR_STRICT_PQ"

// truthy enumerates the values that ProfileFromEnv accepts as "set".
// Anything else, including the empty string, selects [Permissive].
var truthy = map[string]bool{
	"1":    true,
	"true": true,
	"on":   true,
	"yes":  true,
	"y":    true,
}

// ProfileFromEnv returns [Strict] when [EnvVar] is set to a truthy
// value and [Permissive] otherwise. Comparison is case-insensitive.
func ProfileFromEnv() Profile {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvVar)))
	if truthy[v] {
		return Strict()
	}
	return Permissive()
}
