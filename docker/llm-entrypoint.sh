#!/bin/sh
# Single entrypoint for both LLM roles this app needs, selected via LLM_MODE
# so one built image serves both docker-compose services (completion + embed)
# instead of maintaining two near-identical Dockerfiles.
#
# LLM_MODE=completion (default): main generation server, port 11434.
#   -np (parallel slot count) auto-sizes to this container's actual available
#   RAM, mirroring the same formula src/core/resource_guard.py uses for the
#   app's own concurrency semaphore (see that file for the full explanation):
#   baseline ~8GB fixed overhead, ~2.5GB KV cache per additional full-context
#   slot, 0.85 safety margin, floor of 1. Duplicated here in shell because
#   this is a separate container image with no Python app code to import
#   resource_guard.py from.
# LLM_MODE=embedding: embedding-only server, port 11435, nomic-embed-text.
#   No -np/context concerns here -- single-purpose, short requests.
#
# Reads cgroup memory limits first (this container's actual allowance, which
# may be less than host total RAM if the operator set --memory on it),
# falling back to /proc/meminfo (host total) if no cgroup limit is set.

LLM_MODE="${LLM_MODE:-completion}"

detect_total_mem_gb() {
    if [ -f /sys/fs/cgroup/memory.max ]; then
        limit=$(cat /sys/fs/cgroup/memory.max)
        if [ "$limit" != "max" ]; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
        if [ "$limit" -lt 1000000000000 ] 2>/dev/null; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    awk -v k="$kb" 'BEGIN { printf "%.2f", k / 1048576 }'
}

if [ "$LLM_MODE" = "embedding" ]; then
    echo "[LLM ENTRYPOINT] Starting embedding server (nomic-embed-text) on port 11435."
    exec /app/llama-server \
        --host 0.0.0.0 --port 11435 \
        -m /models/nomic-embed-text-v1.5.f16.gguf \
        -t "${EMBED_THREADS:-4}" \
        --embedding
fi

# completion mode
FIXED_OVERHEAD_GB="${RESOURCE_GUARD_FIXED_OVERHEAD_GB:-8}"
PER_SLOT_GB="${RESOURCE_GUARD_PER_SLOT_GB:-2.5}"
SAFETY_MARGIN="${RESOURCE_GUARD_SAFETY_MARGIN:-0.85}"

TOTAL_GB=$(detect_total_mem_gb)
SLOTS=$(awk -v t="$TOTAL_GB" -v o="$FIXED_OVERHEAD_GB" -v p="$PER_SLOT_GB" -v m="$SAFETY_MARGIN" '
    BEGIN {
        usable = (t * m) - o
        slots = int(usable / p)
        if (slots < 1) slots = 1
        print slots
    }
')

if [ -n "$LLM_SLOTS_OVERRIDE" ]; then
    SLOTS="$LLM_SLOTS_OVERRIDE"
    echo "[LLM ENTRYPOINT] LLM_SLOTS_OVERRIDE set -- using $SLOTS slots instead of auto-detection."
else
    echo "[LLM ENTRYPOINT] Detected ${TOTAL_GB}GB available -> auto-sized to $SLOTS concurrent slot(s)."
fi

exec /app/llama-server \
    --host 0.0.0.0 --port 11434 \
    -m /models/google_gemma-4-E4B-it-Q4_K_M.gguf \
    -c 0 -np "$SLOTS" \
    -t "${LLM_THREADS:-4}" \
    -b 2048 -ub 512 \
    --cont-batching \
    --flash-attn on
