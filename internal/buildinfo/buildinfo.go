package buildinfo

import "fmt"

// These values are populated with -ldflags for release builds. Keeping safe
// defaults makes local `go run` and test builds useful without extra tooling.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("driftnet2 %s (commit %s, built %s)", Version, Commit, Date)
}
