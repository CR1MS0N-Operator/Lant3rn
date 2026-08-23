// Fake grype for runner tests: emits a minimal grype JSON report.
// Built by the test into a temp dir; not part of any package build.
// FAKE_GRYPE_EXIT=N forces exit code N with a stderr message.
package main

import (
	"fmt"
	"os"
)

func main() {
	if v := os.Getenv("FAKE_GRYPE_EXIT"); v != "" {
		fmt.Fprintln(os.Stderr, "fake grype: forced failure")
		code := 1
		fmt.Sscanf(v, "%d", &code)
		os.Exit(code)
	}
	fmt.Print(`{"matches":[{"vulnerability":{"id":"CVE-2024-1234","severity":"High"}}],` +
		`"source":{"target":"aclguard"}}`)
}
