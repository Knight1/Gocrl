package main

import (
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

func linting(data []byte) {
	parsed, err := x509.ParseRevocationList(data)
	if err != nil {
		// If x509.ParseRevocationList fails, the RevocationList is too broken to lint.
		fmt.Println("LINT: unable to parse revocation List:", err)
		return
	}

	zlintResultSet := zlint.LintRevocationList(parsed)

	var errors int
	if len(zlintResultSet.Results) == 0 {
		fmt.Println("LINT: No results found")
	} else {
		for _, result := range zlintResultSet.Results {
			if result.Status == lint.Error ||
				result.Status == lint.Fatal ||
				result.Status == lint.Warn {
				errors++
				fmt.Println("LINT: Result:", result.Status)
				fmt.Println(result.LintMetadata.Description)
				fmt.Println(result.LintMetadata.Name)
				//if result.Status ==
				fmt.Println("LINT: Error:")
				fmt.Println(result.LintMetadata.Description)
				fmt.Println(result.LintMetadata.Name)
				fmt.Println("Status:", result.Status)
			}
		}
	}
	if errors > 0 {
		fmt.Println("  LINT: Errors found:", errors)
	} else if errors == 0 {
		fmt.Println("  LINT: No problems found")
	}
}
