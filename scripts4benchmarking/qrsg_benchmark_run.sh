#!/usr/bin/env bash
# Run REAL QRSG Kotlin analyzers against benign/malicious manifests using local JVM unit tests.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: ./qrsg_benchmark_run.sh offline|online [OPTIONS]

Options:
  --root DIR          Dataset root, default ./qrsg_benchmark
  --out FILE          Result CSV, default ROOT/results/{mode}.csv
  --limit N           First N test cases in deterministic shuffled order (0 = all)
  --seed N            Shuffle seed, default 42
  --delay-ms N        Delay after online API calls, default 1200 milliseconds
  --yes-send-urls     Explicitly authorize sending full URLs (except #fragment) to Google
  --retry-unavailable Retry existing UNAVAILABLE_* rows; keep an automatic backup

Examples:
  ./qrsg_benchmark_run.sh offline --limit 20
  ./qrsg_benchmark_run.sh offline
  ./qrsg_benchmark_run.sh online --limit 10 --yes-send-urls
  ./qrsg_benchmark_run.sh online --yes-send-urls

Online mode: requires an API key in QRSG_BENCHMARK_API_KEY or QRSG_SAFE_BROWSING_API_KEY.
No scanned URL is ever opened. The online request goes ONLY to Google Safe Browsing.
HELP
}

if [[ $# -eq 0 ]] || [[ "${1:-}" == --help ]] || [[ "${1:-}" == -h ]]; then usage; exit 0; fi
mode="$1"; shift
if [[ "$mode" != offline && "$mode" != online ]]; then echo 'ERROR: choose offline or online' >&2; usage; exit 2; fi
root="${PWD}/qrsg_benchmark"
out=""
limit=0
seed=42
delay_ms=1200
send_urls=NO
retry_unavailable=NO
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) root="${2:?missing value}"; shift 2;;
    --out) out="${2:?missing value}"; shift 2;;
    --limit) limit="${2:?missing value}"; shift 2;;
    --seed) seed="${2:?missing value}"; shift 2;;
    --delay-ms) delay_ms="${2:?missing value}"; shift 2;;
    --yes-send-urls) send_urls=YES; shift;;
    --retry-unavailable) retry_unavailable=YES; shift;;
    -h|--help) usage; exit 0;;
    *) echo "ERROR: unknown option $1" >&2; exit 2;;
  esac
done
for value in "$limit" "$delay_ms"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo 'ERROR: --limit and --delay-ms must be >= 0' >&2; exit 2; }
done
[[ "$seed" =~ ^-?[0-9]+$ ]] || { echo 'ERROR: invalid seed' >&2; exit 2; }
[[ -x ./gradlew ]] || { echo 'ERROR: run this script from the ROOT of your QRSG Git repository' >&2; exit 2; }
[[ -f app/src/test/java/com/qrsg/app/experiment/QrsgDatasetBenchmarkTest.kt ]] || {
  echo 'ERROR: Kotlin benchmark test not installed in app/src/test/java/...' >&2; exit 2;
}
root="$(realpath "$root")"
[[ -f "$root/benign/manifest.csv" && -f "$root/malicious/manifest.csv" ]] || {
  echo "ERROR: manifests missing from $root" >&2; exit 2;
}
if [[ -z "$out" ]]; then out="$root/results/$mode.csv"; fi
mkdir -p "$(dirname "$out")"
out="$(realpath -m "$out")"

if [[ "$mode" == online ]]; then
  echo 'PRIVACY: Online mode submits the FULL URL (path and query included, fragment excluded)'
  echo '         to Google Safe Browsing. Do not use URLs carrying sensitive tokens.'
  if [[ "$send_urls" != YES ]]; then
    read -r -p 'Type YES to allow this benchmark to send dataset URLs to Google: ' reply
    [[ "$reply" == YES ]] || { echo 'Online benchmark cancelled.' >&2; exit 2; }
    send_urls=YES
  fi
  if [[ -z "${QRSG_BENCHMARK_API_KEY:-${QRSG_SAFE_BROWSING_API_KEY:-}}" ]]; then
    read -r -s -p 'Safe Browsing v5 API key (not saved): ' QRSG_BENCHMARK_API_KEY
    echo
    export QRSG_BENCHMARK_API_KEY
  fi
  [[ -n "${QRSG_BENCHMARK_API_KEY:-${QRSG_SAFE_BROWSING_API_KEY:-}}" ]] || {
    echo 'ERROR: empty API key' >&2; exit 2;
  }
fi

export QRSG_BENCHMARK_ROOT="$root"
export QRSG_BENCHMARK_OUTPUT="$out"
export QRSG_BENCHMARK_MODE="$mode"
export QRSG_BENCHMARK_LIMIT="$limit"
export QRSG_BENCHMARK_SEED="$seed"
export QRSG_BENCHMARK_DELAY_MS="$delay_ms"
export QRSG_BENCHMARK_SEND_URLS="$send_urls"
export QRSG_BENCHMARK_RETRY_UNAVAILABLE="$retry_unavailable"

# Minimal experiment provenance (never contains URLs or the API key).
provenance="${out}.provenance.txt"
if [[ ! -f "$provenance" ]]; then
  {
    echo "created_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_head=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "mode=$mode"
    echo "seed=$seed"
    echo "initial_limit=$limit"
    echo "api_delay_ms=$delay_ms"
    sha256sum "$root/benign/manifest.csv" "$root/malicious/manifest.csv"
    java -version 2>&1
  } > "$provenance"
fi

# Do NOT echo full URLs or the API key. The Gradle test task is forced to run each time.
 #Force benchmark test to rerun without rebuilding KSP.
rm -rf app/build/test-results/testDebugUnitTest

./gradlew :app:testDebugUnitTest \
    --tests 'com.qrsg.app.experiment.QrsgDatasetBenchmarkTest' \
    --no-build-cache --console=plain

echo "Wrote CSV: $out"
if [[ -f "$out" ]]; then
  python3 qrsg_benchmark_metrics.py --input "$out"
fi
