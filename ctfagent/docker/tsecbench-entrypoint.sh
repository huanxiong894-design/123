#!/bin/sh
set -eu

# This image is hosted-mode only: pin model traffic to the platform gateway even
# if the caller supplies a different CTFAGENT_LLM_URL at runtime.
export CTFAGENT_LLM_URL='http://api.deepseek.com.tsecbench.gw/v1'
export CTFAGENT_MODEL="${CTFAGENT_MODEL:-deepseek-chat}"

# Accept either the ctfagent variable or the conventional provider variable;
# never print the value and never put it in the image.
if [ -z "${CTFAGENT_API_KEY:-}" ] && [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    export CTFAGENT_API_KEY="$DEEPSEEK_API_KEY"
fi

missing=''
[ -n "${CTFAGENT_API_KEY:-}" ] || missing="$missing CTFAGENT_API_KEY (or DEEPSEEK_API_KEY)"
[ -n "${BENCHMARK_BASE_URL:-}" ] || missing="$missing BENCHMARK_BASE_URL"
[ -n "${BENCHMARK_TOKEN:-}" ] || missing="$missing BENCHMARK_TOKEN"
if [ -n "$missing" ]; then
    echo "Missing required runtime environment variable(s):$missing" >&2
    exit 64
fi

# Start solving immediately. The report and checkpoints stay in ephemeral
# runtime paths and are not part of the image/package.
exec /usr/local/bin/ctfagent run \
    --platform tsec \
    --concurrency 3 \
    --max-steps 40 \
    --rounds 20m,20m \
    --checkpoint-dir /tmp/ctfagent-checkpoints \
    --out /tmp/ctfagent-report.json
