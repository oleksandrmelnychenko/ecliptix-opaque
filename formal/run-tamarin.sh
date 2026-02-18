#!/bin/bash
# Run Tamarin Prover on Hybrid PQ-OPAQUE model and save output to logs.
# Usage: ./run-tamarin.sh [--lemma NAME | --lemma=NAME] [--background]
#   --lemma NAME   Prove only the named lemma (faster)
#   --background   Run in background, show log path
#
# Run from project root or formal/: ./formal/run-tamarin.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/tamarin_proof_$(date +%Y%m%d_%H%M%S).log"

LEMMA=""
BG=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --lemma=*)
      LEMMA="${1#--lemma=}"
      ;;
    --lemma)
      shift
      if [ "$#" -eq 0 ]; then
        echo "Error: --lemma requires a value"
        exit 1
      fi
      LEMMA="$1"
      ;;
    --background)
      BG=1
      ;;
    *)
      echo "Error: unknown option: $1"
      echo "Usage: ./run-tamarin.sh [--lemma NAME | --lemma=NAME] [--background]"
      exit 1
      ;;
  esac
  shift
done

echo "=== Tamarin Prover — Hybrid PQ-OPAQUE ==="
echo "Log: $SCRIPT_DIR/$LOG_FILE"
echo ""

if [ -n "$LEMMA" ]; then
  echo "Proving single lemma: $LEMMA"
  CMD="tamarin-prover hybrid_pq_opaque.spthy --prove=$LEMMA -v"
else
  echo "Proving all lemmas (30–120 min typical)"
  CMD="tamarin-prover hybrid_pq_opaque.spthy --prove -v"
fi

if [ "$BG" -eq 1 ]; then
  $CMD 2>&1 | tee "$LOG_FILE" &
  echo "Running in background. Monitor: tail -f $LOG_FILE"
else
  $CMD 2>&1 | tee "$LOG_FILE"
  echo ""
  echo "Done. Full log: $LOG_FILE"
fi
