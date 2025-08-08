# This tool downloads the CCADB Intermediate CRL Lists and subsequent CRLs for all publicly trusted Certificates in Mozilla Firefox, Chrome, .. and checks for Errors.

# Gocrl

Gocrl is a Go project for working with CRLs (Certificate Revocation Lists) and related certificate utilities. It leverages several third-party libraries for TOML parsing, public suffix handling, cryptography, and certificate linting.

## Features
- Certificate Revocation List (CRL) processing
- Certificate validation and linting
- TOML configuration support
- Utilities for public suffixes and cryptography

## Project Structure
- `main.go`: Entry point of the application
- `check.go`, `linting.go`, `update.go`: Core logic for CRL and certificate operations
- `vendor/`: Third-party dependencies
- `go.mod`, `go.sum`: Go module files

## Getting Started
### Prerequisites
- Go 1.18 or newer

### Installation
Clone the repository:
```sh
git clone https://github.com/Knight1/Gocrl.git
cd Gocrl
```

### Usage
Run the main application:
```sh
go run main.go
```

## Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.
