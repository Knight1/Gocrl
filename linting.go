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
		// This is the second check but with zcrypto. zcrypto is a bit lazy'r than Golangs x509 implementation.
		fmt.Println("  LINT: unable to parse revocation List:", err)
		return
	}

	var zlintResultSet *zlint.ResultSet
	isCA := true
	switch {
	case isCA:
		reg, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
			IncludeNames: []string{"e_crl_next_update_invalid"},
		})
		if err != nil {
			panic(err)
		}

		toml := `
[e_crl_next_update_invalid]
SubscriberCRL = false
`

		cfg, err := lint.NewConfigFromString(toml)
		if err != nil {
			panic(err)
		}
		reg.SetConfiguration(cfg)

		zlintResultSet = zlint.LintRevocationListEx(parsed, reg)

	default:
		zlintResultSet = zlint.LintRevocationList(parsed)
	}

	var errors int
	if len(zlintResultSet.Results) == 0 {
		if *debugLogging {
			fmt.Println("  LINT: No results found")
		}
	} else {
		for _, result := range zlintResultSet.Results {
			if result.Status == lint.Error ||
				result.Status == lint.Fatal ||
				result.Status == lint.Warn {
				errors++
				if *debugLogging || *showLintErrors {
					fmt.Println("  LINT: Error:", result.Status)
					fmt.Println(result.LintMetadata.Description)
					fmt.Println(result.LintMetadata.Name)
				}
			}
		}
	}
	if errors > 0 {
		fmt.Println("  LINT: Errors found:", errors)
		fmt.Println("  LINT: AIA:", parsed.AuthorityKeyId, "Issuer:", parsed.Issuer.String())
	} else if errors == 0 {
		if *debugLogging {
			fmt.Println("  LINT: No problems found")
		}
	}
}
