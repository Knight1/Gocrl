package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ccadbURL         = "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport"
	outputBaseDir    = "crls"
	fieldIssuer      = "Issuer"
	fieldSubject     = "Subject"
	fieldFullCRL     = "Full CRL Issued By This CA"
	fieldPartitioned = "JSON Array of Partitioned CRLs" // not valid JSON
)

func updateCRLs() {
	fmt.Println("Updating CRLs... Downloading Mozilla CCADB Root and Intermediates with Trust-Bit set")
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

	requiredFields := []string{fieldSubject, fieldIssuer, fieldFullCRL, fieldPartitioned}
	for _, f := range requiredFields {
		if _, ok := index[f]; !ok {
			panic(fmt.Sprintf("missing field: %s", f))
		}
	}

	fmt.Println("Download and parsing done. Downloading CRLs.")
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Skipping row due to error: %v\n", err)
			continue
		}

		subject := record[index[fieldSubject]]
		issuer := sanitize(record[index[fieldIssuer]])
		fullCRL := strings.TrimSpace(record[index[fieldFullCRL]])
		partCRLJSON := strings.TrimSpace(record[index[fieldPartitioned]])

		_, orgName := parseIssuerDN(issuer)

		dir := filepath.Join(outputBaseDir, orgName, "/", subject)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Failed to create dir %s: %v\n", dir, err)
			continue
		}

		if fullCRL != "" {
			savePath := filepath.Join(dir, filepath.Base(fullCRL))
			downloadCRL(fullCRL, savePath)
		}

		if partCRLJSON != "" && partCRLJSON != "[]" {
			urls, err := parsePartitionedURLs(partCRLJSON)
			if err != nil {
				fmt.Printf("bad partitioned‑CRL list for %q: %v\n", issuer, err)
				continue
			}
			for _, url := range urls {
				save := filepath.Join(dir, fmt.Sprintf(filepath.Base(url)))
				downloadCRL(url, save)
			}
		}
	}
	fmt.Println("Done!")
}

func downloadCRL(url, destPath string) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Do(req)
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
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}

func parsePartitionedURLs(raw string) ([]string, error) {
	trimmed := strings.TrimPrefix(strings.TrimSuffix(raw, "]"), "[")
	parts := strings.Split(trimmed, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}

	// filter out empty entries
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

func parseIssuerDN(dn string) (cn, org string) {
	parts := strings.FieldsFunc(dn, func(r rune) bool {
		return r == ',' || r == ';'
	})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			cn = strings.TrimPrefix(part, "CN=")
		} else if strings.HasPrefix(part, "O=") {
			org = strings.TrimPrefix(part, "O=")
		}
	}
	return
}
