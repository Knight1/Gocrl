package main

import (
	"bytes"
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
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
		fmt.Println("Error downloading Mozilla CCADB Root CA certificate:", err)
		return
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	headers, err := reader.Read()
	if err != nil {
		fmt.Println("Error parsing Mozilla CCADB Root CA CSV Headers:", err)
		return
	}

	// Map header names to indices
	index := map[string]int{}
	for i, h := range headers {
		index[strings.TrimSpace(h)] = i
	}

	requiredFields := []string{fieldSubject, fieldIssuer, fieldFullCRL, fieldPartitioned}
	for _, f := range requiredFields {
		if _, ok := index[f]; !ok {
			fmt.Println("Missing required field in csv:", f)
			return
		}
	}

	fmt.Println("Download and parsing done. Downloading CRLs.")
	var wg sync.WaitGroup
	for {

		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Skipping row due to error: %v\n", err)
			continue
		}

		subjectRaw := record[index[fieldSubject]]
		issuer := sanitize(record[index[fieldIssuer]])
		fullCRL := strings.TrimSpace(record[index[fieldFullCRL]])
		partCRLJSON := strings.TrimSpace(record[index[fieldPartitioned]])

		_, orgName := parseIssuerDN(issuer)
		subject, _ := parseIssuerDN(subjectRaw)

		dir := filepath.Join(outputBaseDir, orgName, "/", subject)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Failed to create dir %s: %v\n", dir, err)
			continue
		}

		if fullCRL != "" {
			wg.Add(1)
			savePath := filepath.Join(dir, filepath.Base(fullCRL))
			go func() {
				defer wg.Done()
				downloadCRL(fullCRL, savePath)
			}()
		}

		if partCRLJSON != "" && partCRLJSON != "[]" {
			urls, err := parsePartitionedURLs(partCRLJSON)
			if err != nil {
				fmt.Println("bad partitioned‑CRL list for", issuer, "error:", err)
				continue
			}
			for _, url := range urls {
				wg.Add(1)
				save := filepath.Join(dir, fmt.Sprintf(filepath.Base(url)))
				go func() {
					defer wg.Done()
					downloadCRL(url, save)
				}()
			}
		}
	}
	wg.Wait()
	fmt.Println("Done!")
}

func downloadCRL(url, destPath string) {
	localETag, err := computeETag(destPath)
	if err != nil {
		fmt.Printf("Failed to compute ETag. File might be missing: %v\n", err)
		return
	}

	url = cleanURL(url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("failed to create HEAD request:", err)
		return
	}

	client := &http.Client{
		Timeout: time.Second * clientTimeout,
	}

	if localETag != "" {
		req.Header.Set("If-None-Match", localETag)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Download failed for %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		if *debugLogging {
			fmt.Println("Skipped download, CRL not modified", url)
		}
		return
	}

	if resp.StatusCode != 200 {
		fmt.Printf("Non-200 for %s: %d\n", url, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response body for", url, err)
		return
	}

	if len(body) == 0 {
		fmt.Println("Empty response body", url, resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		fmt.Printf("File create error for %s: %v\n", destPath, err)
		return
	}
	defer out.Close()

	reader := bytes.NewReader(body)
	written, err := io.Copy(out, reader)
	if err != nil || written != int64(len(body)) {
		fmt.Println("Write error for", destPath, "Written:", written, "error:", err)
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

func computeETag(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // no file yet
		}
		return "", err
	}
	defer f.Close()

	hasher := md5.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", err
	}

	sum := hasher.Sum(nil)
	// wrap in quotes so it looks like a real ETag header
	return `"` + hex.EncodeToString(sum) + `"`, nil
}

// Sometimes there are wild things in the URLs..
func cleanURL(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
