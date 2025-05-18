package main

import (
	"flag"
	"fmt"
	"runtime"
	"time"
)

var (
	// BuildTime holds the timestamp (RFC3339) of the last build.
	BuildTime string
	// CommitHash holds the Git commit SHA at build time.
	CommitHash string
	// GOARCH holds the target architecture string (e.g. "amd64", "arm64") injected at build time.
	GOARCH            string
	debugLogging      *bool
	showLintErrors    *bool
	clientTimeout     time.Duration = 60 // Seconds
	intermediatesFile               = "intermediates.pem"
)

func main() {
	updateFlag := flag.Bool("update", true, "update crl files")
	checkFlag := flag.Bool("check", true, "check crl files")
	showLintErrors = flag.Bool("show-lint-errors", true, "show linting errors")
	// ocspFlag := flag.Bool("ocsp", false, "check ocsp responses")
	debugLogging = flag.Bool("debug", false, "debug mode")
	flag.Parse()

	// Print Version Information
	fmt.Println("Starting Certificate Revocation List Monitor.")
	fmt.Println("Go version:", runtime.Version(),
		"BuildTime:", BuildTime,
		"CommitHash:", CommitHash,
		"GOARCH:", GOARCH)

	if *debugLogging {
		fmt.Println("Debug logging enabled")
	}

	if *checkFlag {
		check()
	}

	if *updateFlag {
		updateCRLs()
	}

}
