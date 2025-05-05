package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	ccadbURL         = "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport"
	outputBaseDir    = "crls"
	fieldIssuer      = "Issuer"
	fieldFullCRL     = "Full CRL Issued By This CA"
	fieldPartitioned = "JSON Array of Partitioned CRLs"
)

func updateCRLs() {
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

	// Map header names to indices
	index := map[string]int{}
	for i, h := range headers {
		index[strings.TrimSpace(h)] = i
	}

	requiredFields := []string{fieldIssuer, fieldFullCRL, fieldPartitioned}
	for _, f := range requiredFields {
		if _, ok := index[f]; !ok {
			panic(fmt.Sprintf("missing field: %s", f))
		}
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Skipping row due to error: %v\n", err)
			continue
		}

		issuer := sanitize(record[index[fieldIssuer]])
		fullCRL := strings.TrimSpace(record[index[fieldFullCRL]])
		partCRLJSON := strings.TrimSpace(record[index[fieldPartitioned]])

		dir := filepath.Join(outputBaseDir, issuer)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Failed to create dir %s: %v\n", dir, err)
			continue
		}

		if fullCRL != "" {
			savePath := filepath.Join(dir, "full_"+filepath.Base(fullCRL))
			downloadCRL(fullCRL, savePath)
		}

		if partCRLJSON != "" {
			urls, err := parsePartitionedURLs(partCRLJSON)
			if err != nil {
				fmt.Printf("bad partitioned‑CRL list for %q: %v\n", issuer, err)
				continue
			}
			for i, url := range urls {
				save := filepath.Join(dir, fmt.Sprintf("part%d_%s", i+1, filepath.Base(url)))
				downloadCRL(url, save)
			}
		}
	}
	fmt.Println("Done!")
}

func downloadCRL(url, destPath string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Download failed for %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Non-200 for %s: %d\n", url, resp.StatusCode)
		return
	}

	out, err := os.Create(destPath)
	if err != nil {
		fmt.Printf("File create error for %s: %v\n", destPath, err)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		fmt.Printf("Write error for %s: %v\n", destPath, err)
	}
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "*", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "\"", "_")
	s = strings.ReplaceAll(s, "<", "_")
	s = strings.ReplaceAll(s, ">", "_")
	s = strings.ReplaceAll(s, "|", "_")
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}

// parsePartitionedURLs accepts either:
//   - a proper JSON array of strings, eg ["http://…","http://…"]
//   - or a “bare” bracketed list without quotes, eg [http://… , http://…]
func parsePartitionedURLs(raw string) ([]string, error) {
	// try valid JSON first
	var urls []string
	if err := json.Unmarshal([]byte(raw), &urls); err == nil {
		return urls, nil
	}

	// fallback: strip [ and ], split on commas
	trimmed := strings.TrimPrefix(strings.TrimSuffix(raw, "]"), "[")
	parts := strings.Split(trimmed, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	// filter out any empty entries
	var out []string
	for _, u := range parts {
		if u != "" {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no URLs found in %q", raw)
	}
	return out, nil
}
