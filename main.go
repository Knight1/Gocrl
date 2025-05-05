package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	ccadbURL     = "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport"
	outputDir    = "crls"
	crlFieldName = "Full CRL Issued By This CA"
)

func main() {
	resp, err := http.Get(ccadbURL)
	if err != nil {
		panic(fmt.Errorf("failed to download CSV: %w", err))
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	headers, err := reader.Read()
	if err != nil {
		panic(fmt.Errorf("failed to read CSV headers: %w", err))
	}

	crlIndex := -1
	for i, h := range headers {
		if strings.TrimSpace(h) == crlFieldName {
			crlIndex = i
			break
		}
	}
	if crlIndex == -1 {
		panic("CRL Distribution Point column not found")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		panic(fmt.Errorf("failed to create output directory: %w", err))
	}

	seen := make(map[string]bool)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Skipping row due to error: %v\n", err)
			continue
		}

		url := strings.TrimSpace(record[crlIndex])
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true

		if err := downloadCRL(url); err != nil {
			fmt.Printf("Failed to download CRL %s: %v\n", url, err)
		}
	}
	fmt.Println("Done!")
}

func downloadCRL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("http get failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}

	filename := sanitizeFilename(filepath.Base(url))
	path := filepath.Join(outputDir, filename)

	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("file create failed: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "&", "_")
	name = strings.ReplaceAll(name, "=", "_")
	if name == "" || name == "." || name == ".." {
		name = "default.crl"
	}
	return name
}
