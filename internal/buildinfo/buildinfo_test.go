package buildinfo

import (
	"strings"
	"testing"
)

func TestStringIncludesBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldVersion, oldCommit, oldDate })

	Version, Commit, Date = "v1.2.0", "abc1234", "2026-11-05T12:00:00Z"
	got := String()
	for _, want := range []string{"v1.2.0", "abc1234", "2026-11-05T12:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("String() = %q, missing %q", got, want)
		}
	}
}
