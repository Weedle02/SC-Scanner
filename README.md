# SC-Scanner
# Source Code Security Scanner

A parallel-processing security scanner that checks GitHub repositories for sensitive data exposure using TruffleHog and Gitleaks.

## Features

- **Parallel Repository Scanning**: Processes multiple repositories simultaneously
- **Secret Detection**: Identifies verified secrets using TruffleHog
- **Leak Detection**: Finds credential leaks with Gitleaks
- **Clean Reporting**: Only shows results when findings exist
- **Error Resilient**: Continues scanning even if some repositories fail

## Requirements

- Python 3.7+
- Git
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)

## Installation

Clone repository:
```bash
git clone https://github.com/weedle02/security-scanner.git
cd security-scanner
```

Install Python dependencies:

```bash
pip install gitpython colorama
```

Install security tools:

For Debian/Ubuntu
```bash
sudo apt-get install -y trufflehog gitleaks
```

For macOS
```bash
brew install trufflehog gitleaks
```

Create input file with repository URLs:

```bash
echo "https://github.com/example/repo
https://github.com/another/repo" > repos.txt
```

Run scanner:

```bash
python scscanner.py repos.txt
```

## Sample output when clean:

```bash
No findings across all repositories
```

## Sample output with findings:

```bash
https://github.com/example/insecure-repo
--------------------------------------------------
TRUFFLEHOG Findings:
Secret: https://redacted.example.com
Path: config/production.json

GITLEAKS Findings:
Leak: github-pat
File: scripts/deploy.sh:42
```

## Acknowledgments

- **TruffleHog**: by Truffle Security
- **Gitleaks**: by Zricethezav
