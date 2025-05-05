package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func check() {
	baseDir := "crls"
	var totalSize int64
	var totalRevoces int

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".crl" {
			return nil
		}

		fmt.Printf("CRL: %s\n", path)

		size := info.Size()
		totalSize += size
		fmt.Printf("  Size: %d bytes\n", size)

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("  Read error: %v\n\n", err)
			return nil
		}

		// If CRL is PEM-encoded we need to strip headers
		if block, _ := pem.Decode(data); block != nil {
			if block.Type == "X509 CRL" {
				data = block.Bytes
			}
		}

		// Parse downloaded CRL
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			fmt.Printf("  Parse error: %v\n\n", err)
			return nil
		}

		signatureAlgorithm := crl.SignatureAlgorithm
		fmt.Printf("  Signature Algorithm: %s\n", signatureAlgorithm)

		// crl.CheckSignatureFrom()

		issuer := crl.Issuer
		fmt.Printf("  Issuer: %s\n", issuer)

		now := time.Now()
		next := crl.NextUpdate
		fmt.Printf("  NextUpdate: %s\n", next.Format(time.RFC3339))
		if now.After(next) {
			fmt.Printf("  → CRL is expired as of now (%s)\n", now.Format(time.RFC3339))
		} else {
			fmt.Printf("  → CRL is still valid\n")
		}

		// Counting revoked certificates
		revCount := len(crl.RevokedCertificateEntries)
		fmt.Printf("  Revoked entries: %d\n\n", revCount)
		totalRevoces = totalRevoces + revCount

		return nil
	})
	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
		return
	}

	fmt.Printf("Total disk used by CRLs: %.2f MB\n", float64(totalSize)/(1024*1024))
	fmt.Printf("Total revocations: %d\n", totalRevoces)
}
