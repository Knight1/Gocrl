package main

import (
	"flag"
	"fmt"
	"runtime"
)

var (
	BuildTime    string
	CommitHash   string
	GOARCH       string
	debugLogging *bool
)

func main() {
	updateFlag := flag.Bool("update", true, "update crl files")
	checkFlag := flag.Bool("check", true, "check crl files")
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
