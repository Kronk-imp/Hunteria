#!/usr/bin/env bash
# Robust runner for mitmdump + logscan.py + bot.py
# FIX: track true mitmdump PID (not tee) using a FIFO, so stop_mitmdump sends SIGINT to mitmdump
#      and logscan.py's done() always runs without manual Ctrl+C.

set -euo pipefail

# ---------- CONFIG ----------
URLS_FILE="${URLS_FILE:-urls.txt}"       # list of URLs, one per line (# for comments)
OUT_DIR="${LOGSCAN_OUT:-reco}"           # output dir for JSON (logscan.py also uses this)
MITM_HOST="${MITM_HOST:-127.0.0.1}"      # mitmdump listen host
MITM_PORT="${MITM_PORT:-8080}"           # mitmdump listen port
USER_AGENTS="${USER_AGENTS:-useragents.txt}"
PYTHON="${PYTHON:-python3}"
LOGSCAN_SCRIPT="${LOGSCAN_SCRIPT:-./logscan.py}"
BOT_SCRIPT="${BOT_SCRIPT:-./bot.py}"
DEPTH="${DEPTH:-0}"                      # 0 = stay on start page
COMPACT="${LOGSCAN_COMPACT:-1}"          # 1 = compact JSON

# Waiting settings
STABLE_SECS="${STABLE_SECS:-3}"          # seconds of unchanged file size to consider stable
MAX_WAIT_JSON="${MAX_WAIT_JSON:-30}"     # max seconds to wait for stabilization
POST_BOT_GRACE="${POST_BOT_GRACE:-1.2}"  # seconds after bot ends to let XHR/responses flush
BOT_TIMEOUT="${BOT_TIMEOUT:-20}"         # hard timeout (seconds) for bot.py execution

# ----------- UTILS -----------
die() { echo "[run] ❌ $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

wait_file_stable() {
  local f="$1"
  local last_size="" same_count=0 waited=0
  while [[ $waited -lt $MAX_WAIT_JSON ]]; do
    if [[ -f "$f" ]]; then
      local sz
      if sz=$(stat -c%s "$f" 2>/dev/null); then :; else sz=0; fi
      if [[ "$sz" == "$last_size" && -n "$sz" ]]; then
        same_count=$((same_count+1))
        if [[ $same_count -ge $STABLE_SECS ]]; then
          return 0
        fi
      else
        same_count=0
        last_size="$sz"
      fi
    fi
    sleep 1
    waited=$((waited+1))
  done
  return 1
}

pick_latest_json() {
  ls -t "${OUT_DIR}"/ia_pages_*.json 2>/dev/null | head -n1 || true
}

# Globals for mitmdump & logging
MITM_PID=""
TEE_PID=""
LOG_FIFO=""

cleanup_logging_pipeline() {
  # Called after mitmdump stops
  if [[ -n "${TEE_PID:-}" ]] && ps -p "$TEE_PID" >/dev/null 2>&1; then
    kill -TERM "$TEE_PID" 2>/dev/null || true
    wait "$TEE_PID" 2>/dev/null || true
  fi
  if [[ -n "${LOG_FIFO:-}" && -p "$LOG_FIFO" ]]; then
    rm -f "$LOG_FIFO" || true
  fi
}

start_mitmdump() {
  local log_file="$1"
  [[ -n "$log_file" ]] || die "start_mitmdump: log_file missing"

  mkdir -p "$OUT_DIR"

  # Environment for logscan.py
  export LOGSCAN_OUT="$OUT_DIR"
  export LOGSCAN_COMPACT="$COMPACT"

  echo "[run] Lancement mitmdump sur :$MITM_PORT (compact=$COMPACT)" >&2

  # Create a FIFO so we can capture true mitmdump PID and still tee logs
  LOG_FIFO="$(mktemp -u)"
  mkfifo "$LOG_FIFO"
  tee "$log_file" < "$LOG_FIFO" &
  TEE_PID=$!

  # Start mitmdump writing into the FIFO; capture real mitmdump PID
  mitmdump \
    --listen-host "$MITM_HOST" \
    --listen-port "$MITM_PORT" \
    -s "$LOGSCAN_SCRIPT" \
    > "$LOG_FIFO" 2>&1 &
  MITM_PID=$!
}

stop_mitmdump() {
  if [[ -n "${MITM_PID:-}" ]] && ps -p "$MITM_PID" >/dev/null 2>&1; then
    # Send SIGINT to mitmdump to trigger logscan.py done()
    kill -INT "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
  fi
  echo "[run] Arrêt mitmdump (PID ${MITM_PID:-unknown})"
  cleanup_logging_pipeline
}

_launch_bot_raw() {
  local url="$1"
  local proxy="http://${MITM_HOST}:${MITM_PORT}"
  exec "$PYTHON" "$BOT_SCRIPT" \
    --start-url "$url" \
    --user-agents "$USER_AGENTS" \
    --depth "$DEPTH" \
    --proxy "$proxy"
}

launch_bot() {
  local url="$1"
  local proxy="http://${MITM_HOST}:${MITM_PORT}"
  echo "[run] Lancement bot.py (proxy=${proxy}, depth=${DEPTH}, timeout=${BOT_TIMEOUT}s)"

  if command -v timeout >/dev/null 2>&1; then
    timeout --foreground "${BOT_TIMEOUT}s" "$PYTHON" "$BOT_SCRIPT" \
      --start-url "$url" \
      --user-agents "$USER_AGENTS" \
      --depth "$DEPTH" \
      --proxy "$proxy" || true
  else
    _launch_bot_raw "$url" &
    local BOT_PID=$!
    local waited=0
    while ps -p "$BOT_PID" >/dev/null 2>&1; do
      if [[ $waited -ge $BOT_TIMEOUT ]]; then
        echo "[run] ⏱️  bot.py dépasse ${BOT_TIMEOUT}s → kill"
        kill -TERM "$BOT_PID" 2>/dev/null || true
        sleep 0.5
        kill -KILL "$BOT_PID" 2>/dev/null || true
        break
      fi
      sleep 1
      waited=$((waited+1))
    done
    wait "$BOT_PID" 2>/dev/null || true
  fi
}

# ----------- MAIN -----------
have_cmd mitmdump || die "mitmdump not found in PATH"
have_cmd "$PYTHON" || die "python interpreter not found: $PYTHON"
[[ -f "$LOGSCAN_SCRIPT" ]] || die "logscan.py not found at $LOGSCAN_SCRIPT"
[[ -f "$BOT_SCRIPT" ]] || die "bot.py not found at $BOT_SCRIPT"
[[ -f "$USER_AGENTS" ]] || die "useragents file not found: $USER_AGENTS"

URLS=()
if [[ $# -ge 1 ]]; then
  URLS=("$@")
else
  [[ -f "$URLS_FILE" ]] || die "URLs file not found: $URLS_FILE"
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    URLS+=("$line")
  done < "$URLS_FILE"
fi

echo "[run] ${#URLS[@]} URL(s) détectée(s) → traitement séquentiel"

i=0
for START_URL in "${URLS[@]}"; do
  i=$((i+1))
  echo
  echo "================= [$i/${#URLS[@]}] ${START_URL} ================="

  MITM_LOG="$(mktemp)"
  start_mitmdump "$MITM_LOG"

  launch_bot "$START_URL"

  # Small grace for late responses
  sleep "$POST_BOT_GRACE"

  # Stop mitmdump and finalize
  stop_mitmdump

  # Parse the output JSON path
  OUT_JSON="$(awk '/^\[logscan\] Sortie IA: /{print $NF}' "$MITM_LOG" | tail -n1)"
  if [[ -z "${OUT_JSON:-}" ]]; then
    echo "[run] ⚠ Aucun chemin de sortie détecté dans les logs — fallback sur le plus récent"
    OUT_JSON="$(pick_latest_json || true)"
  fi

  if [[ -n "${OUT_JSON:-}" ]]; then
    echo "[run] Attente du fichier JSON et stabilisation (max ${MAX_WAIT_JSON}s, require ${STABLE_SECS}s)..."
    if wait_file_stable "$OUT_JSON"; then
      echo "[run] Fichier stable: $OUT_JSON"
    else
      echo "[run] ⚠ Aucun fichier JSON stable détecté après ${MAX_WAIT_JSON}s — on prendra le plus récent (s'il existe)"
      OUT_JSON="$(pick_latest_json || true)"
    fi
  else
    echo "[run] ⚠ Aucun fichier JSON trouvé du tout dans ${OUT_DIR}"
  fi

  if [[ -n "${OUT_JSON:-}" && -f "$OUT_JSON" ]]; then
    host_part=$(echo "$START_URL" | awk -F/ '{print $3}')
    [[ -n "$host_part" ]] || host_part="unknown-host"
    ts=$(date +"%Y-%m-%d_%H%M%S")
    safe_host=$(echo "$host_part" | tr '/:' '__')
    dest="${OUT_DIR}/${ts}_${safe_host}.json"
    mv -f "$OUT_JSON" "$dest"
    if command -v jq >/dev/null 2>&1; then
      echo "[logscan] ✅ Écrit $(jq -r '.pages | length' "$dest" 2>/dev/null || echo '?') entrées dans $dest"
    else
      echo "[logscan] ✅ Fichier écrit: $dest"
    fi
  else
    echo "[run] ⚠ Aucun fichier JSON à renommer pour cette URL."
  fi

  sleep 1
done

echo
echo "[run] Terminé — ${#URLS[@]} page(s) traitée(s)."
