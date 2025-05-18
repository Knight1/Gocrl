package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var intermediates []*x509.Certificate

func check() {
	baseDir := "crls"
	var totalSize int64
	var totalRevoces int
	var err error

	intermediates, err = loadIntermediates()
	if err != nil {
		fmt.Println("  LINT: unable to load intermediates:", err)
		return
	}

	err = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".crl" {
			return nil
		}

		if *debugLogging {
			fmt.Printf("CRL: %s\n", path)
		}

		size := info.Size()
		totalSize += size
		if *debugLogging {
			fmt.Printf("  Size: %d bytes\n", size)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("  Read error:", err)
			return nil
		}

		// If the File is empty, remove it.
		if len(data) == 0 {
			fmt.Println("  Read error: File empyt:", path)
			err := os.Remove(path)
			if err != nil {
				fmt.Printf("  Failed to remove File: %s error: %s", path, err)
				return err
			}
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
			fmt.Printf("CRL: %s\n", path)
			fmt.Printf("  Parse error: %v\n\n", err)
			return nil
		}

		// find the issuing CA cert
		var issuer *x509.Certificate
		for _, ic := range intermediates {
			if ic.Subject.String() == crl.Issuer.String() {
				issuer = ic
				err = crl.CheckSignatureFrom(issuer)
				if err != nil {
					fmt.Println("  LINT: unable to verify Signature of", path, " CRL:", err)
					// return err\
					break
				}
				break
			}
		}
		if issuer == nil {
			fmt.Println("issuer not found among intermediates:", crl.Issuer.String())
			return nil
		}

		// do it after the first parsing.
		linting(data)

		signatureAlgorithm := crl.SignatureAlgorithm
		if *debugLogging {
			fmt.Printf("  Signature Algorithm: %s\n", signatureAlgorithm)
		}

		issuerName := crl.Issuer
		if *debugLogging {
			fmt.Printf("  Issuer: %s\n", issuerName)
		}
		now := time.Now()
		next := crl.NextUpdate
		if *debugLogging {
			fmt.Printf("  NextUpdate: %s\n", next.Format(time.RFC3339))
			if now.After(next) {
				// AUDIT
				// If we updated the CRL and it is still expired this is a CAB violation.
				fmt.Printf("  → CRL is expired as of now (%s)\n", now.Format(time.RFC3339))
			} else {
				fmt.Printf("  → CRL is still valid\n")
			}
		}
		// Counting revoked certificates
		revCount := len(crl.RevokedCertificateEntries)
		if *debugLogging {
			fmt.Printf("  Revoked entries: %d\n\n", revCount)
		}
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

func loadIntermediates() ([]*x509.Certificate, error) {
	data, err := os.ReadFile("intermediates.pem")
	if err != nil {
		return nil, err
	}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		intermediates = append(intermediates, cert)
	}
	return intermediates, nil
}
