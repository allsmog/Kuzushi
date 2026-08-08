#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

CAMPAIGN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/lib.sh"
trap cleanup EXIT
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/phase-prepare.sh"
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/phase-dynamic.sh"
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/phase-scan.sh"
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/phase-triage-verify.sh"
source "$CAMPAIGN_SCRIPT_DIR/juice-shop-campaign/phase-report.sh"
