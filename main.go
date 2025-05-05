package main

import (
	"flag"
)

func main() {
	flag.Bool("update", false, "update crl files")
	flag.Parse()
	flag.Args()

	/*
		if err := os.MkdirAll(outputBaseDir, 0755); err != nil {
			fmt.Printf("mkdir error: %v\n", err)
			return
		}

	*/

	check()

	updateCRLs()
}
