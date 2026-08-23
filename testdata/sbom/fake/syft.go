// Fake syft for runner tests: emits a minimal CycloneDX document.
// Built by the test into a temp dir; not part of any package build.
// FAKE_SYFT_EXIT=N forces exit code N with a stderr message.
package main

import (
	"fmt"
	"os"
)

func main() {
	if v := os.Getenv("FAKE_SYFT_EXIT"); v != "" {
		fmt.Fprintln(os.Stderr, "fake syft: forced failure")
		code := 1
		fmt.Sscanf(v, "%d", &code)
		os.Exit(code)
	}
	fmt.Print(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"components":[{"type":"application","name":"aclguard","version":"2.0.0"},` +
		`{"type":"library","name":"libldap","version":"2.6.7"}]}`)
}
