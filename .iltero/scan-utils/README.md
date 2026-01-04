# Iltero Compliance Scan Utilities

This directory contains utility scripts for performing compliance scans using the Iltero CLI.

## Prerequisites

### Install Iltero CLI

```bash
pip install iltero-cli
```

### Configure Environment

Set the following environment variables:

```bash
export ILTERO_API_URL="https://api.iltero.io"
export ILTERO_API_TOKEN="your-api-token"
```

Or configure via GitHub repository secrets for CI/CD.

## Usage

### Quick Start

```bash
# Static scan (Checkov)
./scan.sh static network --stack-id abc123

# Plan evaluation (OPA)
./scan.sh plan network --stack-id abc123 --plan-file tfplan.json

# Runtime scan after apply
./scan.sh apply network --stack-id abc123
```

### Options

| Option | Description |
|--------|-------------|
| `--stack-id ID` | Stack ID (required) |
| `--environment ENV` | Environment name [default: development] |
| `--fail-on LEVEL` | Fail threshold: critical, high, medium, low [default: high] |
| `--path PATH` | Path to scan [default: .] |
| `--plan-file FILE` | Plan JSON file (for plan scan) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no violations or within threshold |
| 1 | Violations - violations exceed threshold |
| 2 | Config Error - missing configuration |
| 3 | API Error - communication failure |
| 4 | Scanner Error - Checkov/OPA failure |
| 5 | Auth Error - invalid credentials |

## GitHub Actions Integration

```yaml
- name: Setup Iltero CLI
  run: pip install iltero-cli

- name: Run Compliance Scan
  run: |
    ./.iltero/scan-utils/scan.sh static ${{ matrix.unit.name }} \
      --stack-id ${{ vars.ILTERO_STACK_ID }}
  env:
    ILTERO_API_URL: ${{ vars.ILTERO_API_URL }}
    ILTERO_API_TOKEN: ${{ secrets.ILTERO_API_TOKEN }}
```

## Direct CLI Usage

You can also use the Iltero CLI directly:

```bash
# Static scan with Checkov
iltero scan static ./terraform --stack-id abc123 --unit network

# Plan evaluation with OPA
iltero scan plan tfplan.json --stack-id abc123 --unit network

# View scan status
iltero scan status --run-id <run-id>
```

## Support

For issues, contact support@iltero.io or visit https://docs.iltero.io
