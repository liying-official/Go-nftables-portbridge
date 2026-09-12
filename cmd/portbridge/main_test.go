package main

import (
	"strings"
	"testing"
)

func TestRejectPositionalArgs(t *testing.T) {
	if err := rejectPositionalArgs(nil); err != nil {
		t.Fatalf("empty positional arguments rejected: %v", err)
	}
	err := rejectPositionalArgs([]string{"version"})
	if err == nil || !strings.Contains(err.Error(), `"version"`) {
		t.Fatalf("unexpected validation result: %v", err)
	}
}
