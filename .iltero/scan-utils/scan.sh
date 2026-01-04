#!/bin/bash
# Iltero Compliance Scan Entry Point
# Uses Iltero CLI for local scanning with results submitted via webhook

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ======================================
# Environment Check
# ======================================
check_environment() {
    if [ -z "$ILTERO_API_URL" ]; then
        echo "Error: ILTERO_API_URL environment variable must be set"
        exit 2
    fi

    if [ -z "$ILTERO_API_TOKEN" ]; then
        echo "Error: ILTERO_API_TOKEN environment variable must be set"
        exit 2
    fi
}

# ======================================
# CLI Installation
# ======================================
ensure_iltero_cli() {
    if ! command -v iltero &> /dev/null; then
        echo "Installing iltero-cli..."
        pip install --quiet iltero-cli
    fi
    
    if ! command -v iltero &> /dev/null; then
        echo "❌ Failed to install iltero-cli"
        exit 2
    fi
}

# ======================================
# Help
# ======================================
show_help() {
    cat << EOF
Iltero Compliance Scan Utility

Usage: $0 <scan_type> <unit_name> [options]

Scan Types:
    static      Static analysis scan (Checkov)
    plan        Terraform plan evaluation (OPA)
    apply       Post-apply runtime scan

Options:
    --stack-id ID       Stack ID (required)
    --environment ENV   Environment name [default: development]
    --fail-on LEVEL     Fail on severity: critical, high, medium, low [default: high]
    --path PATH         Path to scan [default: .]
    --plan-file FILE    Path to plan JSON file (for plan scan)
    -h, --help          Show this help message

Environment Variables:
    ILTERO_API_URL      Iltero API URL (required)
    ILTERO_API_TOKEN    Iltero API token (required)

Examples:
    # Static scan
    $0 static network --stack-id abc123

    # Plan evaluation
    $0 plan network --stack-id abc123 --plan-file tfplan.json

    # Runtime scan after apply
    $0 apply network --stack-id abc123

EOF
}

# ======================================
# Main
# ======================================
main() {
    # Parse positional arguments
    SCAN_TYPE="${1:-}"
    UNIT_NAME="${2:-}"
    shift 2 2>/dev/null || true
    
    # Defaults
    STACK_ID=""
    ENVIRONMENT="development"
    FAIL_ON="high"
    SCAN_PATH="."
    PLAN_FILE=""
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --stack-id)
                STACK_ID="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --fail-on)
                FAIL_ON="$2"
                shift 2
                ;;
            --path)
                SCAN_PATH="$2"
                shift 2
                ;;
            --plan-file)
                PLAN_FILE="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 2
                ;;
        esac
    done
    
    # Validate required args
    if [ -z "$SCAN_TYPE" ] || [ -z "$UNIT_NAME" ]; then
        echo "Error: scan_type and unit_name are required"
        show_help
        exit 2
    fi
    
    if [ -z "$STACK_ID" ]; then
        echo "Error: --stack-id is required"
        exit 2
    fi
    
    check_environment
    ensure_iltero_cli
    
    echo "╔════════════════════════════════════════╗"
    echo "║     Iltero Compliance Scanner          ║"
    echo "╠════════════════════════════════════════╣"
    echo "║ Scan Type: $SCAN_TYPE"
    echo "║ Unit: $UNIT_NAME"
    echo "║ Environment: $ENVIRONMENT"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    # Execute scan
    case "$SCAN_TYPE" in
        static)
            iltero scan static "$SCAN_PATH" \
                --stack-id "$STACK_ID" \
                --unit "$UNIT_NAME" \
                --environment "$ENVIRONMENT" \
                --fail-on "$FAIL_ON" \
                --output-format json
            ;;
        plan)
            if [ -z "$PLAN_FILE" ]; then
                echo "Error: --plan-file is required for plan scan"
                exit 2
            fi
            iltero scan plan "$PLAN_FILE" \
                --stack-id "$STACK_ID" \
                --unit "$UNIT_NAME" \
                --environment "$ENVIRONMENT" \
                --fail-on "$FAIL_ON" \
                --output-format json
            ;;
        apply)
            iltero scan apply "$SCAN_PATH" \
                --stack-id "$STACK_ID" \
                --unit "$UNIT_NAME" \
                --environment "$ENVIRONMENT" \
                --fail-on "$FAIL_ON" \
                --output-format json
            ;;
        *)
            echo "❌ Unknown scan type: $SCAN_TYPE"
            echo "Supported types: static, plan, apply"
            exit 2
            ;;
    esac
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo ""
        echo "✅ Compliance scan passed"
    elif [ $EXIT_CODE -eq 1 ]; then
        echo ""
        echo "❌ Compliance violations found (above threshold)"
    else
        echo ""
        echo "❌ Scan failed with error code: $EXIT_CODE"
    fi
    
    exit $EXIT_CODE
}

main "$@"
