#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
uploader.py — Envoie un JSON page_batch_v1 (depuis logscan.py) au modèle OpenAI
et récupère des commandes prêtes à lancer, regroupées par endpoint, format EXACT:

[
  {
    "i": <endpoint id>,
    "vulns": ["sqli","xss", ...],
    "tools": [
      {"tool":"sqlmap","cmd":"..."},
      {"tool":"dalfox","cmd":"..."}
    ]
  }
]

- Mode "stealth" (détection uniquement) imposé par le prompt + post-traitement (enforcer).
- Encodage: on garde l’URL-encoding par défaut des outils; pas de --skip-urlencode sauf autorisation explicite.
- Artefact de sortie: reco/triage/<base>__<pid>.cmds.json
- Utilise Chat Completions (compatible large SDK).
"""

import os
import re
import sys
import json
import time
import glob
import hashlib
import random
from typing import Dict, Any, List
from jsonschema import Draft202012Validator

try:
    from openai import OpenAI
except Exception:
    print("[uploader] Missing 'openai' package. Install with: pip install --upgrade openai jsonschema")
    raise

# ================== Réglages ==================
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # modèle light fiable pour JSON/commandes
INPUT_DIR = os.getenv("INPUT_DIR", "reco")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", os.path.join("reco", "triage"))
MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", "0") or "0")   # 0 = pas de limite
REDACT_COOKIES = os.getenv("REDACT_COOKIES", "0") == "1"      # par défaut OFF pour exécuter les cmd réellement
REDACT_TOKENS = os.getenv("REDACT_TOKENS", "1") == "1"
TIMEOUT_S = int(os.getenv("TIMEOUT_S", "120"))
RETRIES = int(os.getenv("RETRIES", "3"))
MAX_CMDS_PER_EP = int(os.getenv("MAX_CMDS_PER_EP", "2") or "2")
API_KEY = os.getenv("OPENAI_API_KEY")

# Stealth defaults (enforcer appliquera ces garde-fous si le modèle les oublie)
DEFAULT_STEALTH_DELAY = os.getenv("DEFAULT_STEALTH_DELAY", "2")  # secondes
DEFAULT_THREADS = os.getenv("DEFAULT_THREADS", "1")
SQLMAP_TECHNIQUE = os.getenv("SQLMAP_TECHNIQUE", "BE")  # Boolean+Error only
ALLOW_SKIP_URLENCODE = os.getenv("ALLOW_SKIP_URLENCODE", "0") == "1"  # par défaut NON

os.makedirs(OUTPUT_DIR, exist_ok=True)
if not API_KEY:
    print("[uploader] ERROR: OPENAI_API_KEY is not set.")
    sys.exit(1)

client = OpenAI(api_key=API_KEY)

# ================== Whitelists ==================
ALLOWED_VULNS: List[str] = [
    "xss","sqli","cmdi","ssrf","lfi","rfi","redirect","idor","csrf","upload","nosql","xxe","ssti","pp"
]

ALLOWED_TOOLS: List[str] = [
    "sqlmap",        # SQLi
    "dalfox",        # XSS
    "commix",        # CMDi
    "ssrfmap",       # SSRF
    "tplmap",        # SSTI
    "OpenRedireX",   # Open Redirect
    "ppfuzz",        # Prototype Pollution (pp)
    "xsrfprobe",     # CSRF (heuristiques)
    "nosqlmap",      # NoSQLi (plutôt interactif)
    "xxeinjector",   # XXE (souvent artefacts requis)
    "lfisuite"       # LFI / Traversal (souvent interactif)
]

# ================== Schéma de sortie (sans 'why') ==================
OUTPUT_SCHEMA: Dict[str, Any] = {
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "i":     {"type": "integer"},
      "vulns": {"type": "array", "items": {"type":"string", "enum": ALLOWED_VULNS}, "minItems": 1},
      "tools": {
        "type": "array",
        "minItems": 1,
        "items": {
          "type": "object",
          "properties": {
            "tool": {"type":"string", "enum": ALLOWED_TOOLS},
            "cmd":  {"type":"string", "minLength": 8, "maxLength": 4000}
          },
          "required": ["tool","cmd"],
          "additionalProperties": False
        }
      }
    },
    "required": ["i","vulns","tools"],
    "additionalProperties": False
  }
}

# ================== Helpers ==================
def backoff_sleep(attempt: int) -> None:
    time.sleep(min(30, (2 ** attempt) + random.uniform(0, 1.0)))

def redact_string(s: str) -> str:
    """Best-effort masking of secrets in strings."""
    out = s
    out = re.sub(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", r"\1<redacted>", out)
    out = re.sub(r"\b[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b", "<jwt_redacted>", out)
    out = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "<hex_redacted>", out)
    out = re.sub(r"\b[A-Za-z0-9+\/]{40,}={0,2}\b", "<b64_redacted>", out)
    return out

def redact_page(page: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the page with sensitive fields redacted (setc, token-like stuff)."""
    pg = {"u": page.get("u"), "pid": page.get("pid"), "eps": []}
    for ep in page.get("eps", []):
        ep2 = dict(ep)  # shallow copy
        if REDACT_COOKIES and "setc" in ep2 and ep2["setc"]:
            ep2["setc"] = ["<cookie_redacted>" for _ in ep2["setc"]]
        if REDACT_TOKENS:
            rb = ep2.get("rb") or {}
            if rb.get("t") == "text" and isinstance(rb.get("x"), str):
                rb["x"] = redact_string(rb["x"])
                ep2["rb"] = rb
            prms = ep2.get("prms") or {}
            for k, v in list(prms.items()):
                if isinstance(v, str):
                    prms[k] = redact_string(v)
                elif isinstance(v, list):
                    prms[k] = [redact_string(x) if isinstance(x, str) else x for x in v]
            ep2["prms"] = prms
        pg["eps"].append(ep2)
    if MAX_ENDPOINTS and len(pg["eps"]) > MAX_ENDPOINTS:
        pg["eps"] = pg["eps"][:MAX_ENDPOINTS]
    return pg

def strip_to_json_array(text: str) -> str:
    """Extrait le premier tableau JSON valide du texte (tolérant)."""
    start = text.find('[')
    end = text.rfind(']')
    if start != -1 and end != -1 and end > start:
        return text[start:end+1]
    return text

def _ensure_once(cmd: str, token: str) -> str:
    """Ajoute un token s'il est absent (simple)."""
    return cmd if token in cmd else (cmd + f" {token}")

def _strip_token(cmd: str, token: str) -> str:
    """Retire un token s'il est présent (simple, espace-séparé)."""
    parts = cmd.split()
    return " ".join(p for p in parts if p != token)

def enforce_stealth(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ajoute/retire des drapeaux pour rester discret sans casser l’encodage par défaut.
    - sqlmap: force --threads=1, --delay <DEFAULT_STEALTH_DELAY>, --random-agent, --technique=<SQLMAP_TECHNIQUE>.
              retire --skip-urlencode sauf si ALLOW_SKIP_URLENCODE=1. ne touche pas aux headers/cookies.
    - dalfox: ajoute --silence et --delay si absents.
    """
    out = []
    for it in items:
        entry = {"i": it.get("i"), "vulns": it.get("vulns", []), "tools": []}
        for t in it.get("tools", []):
            tool = t.get("tool"); cmd = (t.get("cmd") or "").strip()
            if not tool or not cmd:
                continue
            if tool == "sqlmap":
                cmd = _ensure_once(cmd, f"--threads={DEFAULT_THREADS}")
                cmd = _ensure_once(cmd, f"--delay {DEFAULT_STEALTH_DELAY}")
                cmd = _ensure_once(cmd, "--random-agent")
                cmd = _ensure_once(cmd, f"--technique={SQLMAP_TECHNIQUE}")
                if not ALLOW_SKIP_URLENCODE and "--skip-urlencode" in cmd:
                    cmd = _strip_token(cmd, "--skip-urlencode")
                # On n'ajoute jamais --tamper ici.
            elif tool == "dalfox":
                cmd = _ensure_once(cmd, "--silence")
                cmd = _ensure_once(cmd, f"--delay {DEFAULT_STEALTH_DELAY}")
            # autres outils: on laisse tels quels (faible intensité imposée par prompt)
            entry["tools"].append({"tool": tool, "cmd": cmd})
        out.append(entry)
    return out

# ================== Prompt (stealth générique, encodage par défaut) ==================
PROMPT_FAST = f"""
You are a command generator for a stealthy web pentest scanner.

INPUT: one JSON (schema 'page_batch_v1') for ONE page, with endpoints having:
- i (index), m (method), p (path), sc (status), ct (content-type),
- rb (raw body or excerpt), prms (observed params), x (reflected params),
- ek (error keywords), ai (hints), loc (source), setc (Set-Cookie headers).

GOAL: Return a JSON ARRAY ONLY (no prose). Each item:
{{ "i": <endpoint id>, "vulns": ["sqli","xss",...], "tools": [{{"tool":"sqlmap","cmd":"..."}}, ...] }}

STRICT RULES (stealth-first, encoding-safe):
• PRECISION over recall — if uncertain, EXCLUDE the endpoint.
• Use ONLY parameters that truly exist in the endpoint (from 'prms' or safely inferred JSON keys). You MUST put literal INJECT_HERE at the exact parameter value to be tested.
• Use the tool's DEFAULT URL-encoding behavior. Do NOT use '--skip-urlencode' or tamper flags by default.
• At most {MAX_CMDS_PER_EP} commands per endpoint.
• Commands MUST be single-line, POSIX-shell friendly, properly quoted (use single quotes for --data/--headers).
• REUSE captured context (method, path, headers, cookies). If cookies/headers are present, include them.
• NO destructive actions. DETECTION ONLY.
• Do NOT invent endpoints/params/headers. Do NOT crawl or brute-force.

TOOLS & ALLOWED OPTIONS (whitelist):

- sqlmap (SQLi — detection only)
  Required for stealth: -p <single_target_param>, literal INJECT_HERE at that param in --data, --random-agent, --threads=1, --delay {DEFAULT_STEALTH_DELAY}, --risk=1, --level=1
  If Content-Type implies form or JSON: add --headers 'Content-Type: <exact from INPUT>\\nX-Requested-With: XMLHttpRequest' (when applicable).
  Allowed: -u, --method, --data, -p, --batch, --risk=1, --level=1, --timeout, --threads=1, --technique={SQLMAP_TECHNIQUE}, --random-agent, --headers 'Header: v\\nHeader2: v', --cookie 'k=v'
  Forbidden: --dump, --os-shell, --sql-shell, --file-read, --file-write, --crawl, -r <file>, --tamper, --skip-urlencode

- dalfox (XSS)
  Required for stealth: -p <single_target_param>, --silence, --delay {DEFAULT_STEALTH_DELAY}; include --cookie and a -H 'User-Agent: ...' when available.
  Allowed: dalfox url '<URL>', -H 'Header: v', --header 'Header: v', --cookie 'k=v', -p <param>, --silence, --follow-redirects, --timeout <s>, --delay <s>
  Forbidden: crawling, brute-force, large wordlists

- commix (CMDi — detection-only profile)
  Allowed: -u/--url '<URL>', --method <GET|POST>, --data 'a=1&b=INJECT', --cookie 'k=v', --user-agent '...', --referer '...', --batch, --timeout <s>
  Forbidden: os-shell, reverse shells, file read/write, brute-force flags

- ssrfmap (SSRF — requires raw request file)
  Allowed: ssrfmap -r <raw_request.req> -p <param>
  Notes: <raw_request.req> MUST be a Burp-style raw HTTP request generated by the pipeline. Use OAST only if authorized in INPUT ai.

- tplmap (SSTI)
  Allowed: tplmap -u '<URL>', --method <GET|POST>, --data 'k=v', --header 'Cookie: k=v', --header 'Header: v'
  Forbidden: os-shell/RCE modes, file ops

- OpenRedireX (Open Redirect)
  Preferred: OpenRedireX -l urls.txt -p <param> [--cookie 'k=v'] [-H 'Header: v']
  Minimal:  echo '<URL>' | OpenRedireX -p <param> [--cookie 'k=v'] [-H 'Header: v']

- ppfuzz (Prototype Pollution — client-side)
  Allowed: echo '<URL>' | ppfuzz   OR   ppfuzz -l urls.txt

- xsrfprobe (CSRF — heuristics)
  Allowed: xsrfprobe -u '<URL>'

DISABLED BY DEFAULT in auto-cmd mode (enable only if pipeline supplies artifacts/wrappers):
- nosqlmap (interactive by default)
- xxeinjector (needs payload files/OAST)
- lfisuite (interactive/TUI)

OUTPUT FORMAT (JSON array only, no prose):
[
  {{
    "i": 5,
    "vulns": ["sqli","xss"],
    "tools": [
      {{"tool":"sqlmap","cmd":"sqlmap -u 'http://host/path' --method POST --data 'u=user@ex.com&p=INJECT_HERE' -p p --batch --risk=1 --level=1 --technique={SQLMAP_TECHNIQUE} --threads=1 --delay {DEFAULT_STEALTH_DELAY} --random-agent --headers 'Content-Type: application/x-www-form-urlencoded\\nX-Requested-With: XMLHttpRequest' --cookie 'sid=...'" }},
      {{"tool":"dalfox","cmd":"dalfox url 'http://host/path?q=INJECT_HERE' -p q --silence --delay {DEFAULT_STEALTH_DELAY} -H 'User-Agent: UA' --cookie 'sid=...'" }}
    ]
  }}
]
Return ONLY the JSON array.
"""

# ================== Appel modèle (Chat Completions) ==================
def call_model_chat(page_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    messages = [
        {"role": "system", "content": PROMPT_FAST.strip()},
        {"role": "user", "content": json.dumps(page_obj, ensure_ascii=False)}
    ]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0,
        timeout=TIMEOUT_S
    )
    text = resp.choices[0].message.content or ""
    text = strip_to_json_array(text)
    data = json.loads(text)
    Draft202012Validator(OUTPUT_SCHEMA).validate(data)
    return data

# ================== Routine ==================
def stable_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]

def process_file(path: str) -> None:
    base = os.path.basename(path)
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    # pages dans le fichier
    pages = []
    if isinstance(obj, dict) and "pages" in obj:
        pages = obj["pages"]
    elif isinstance(obj, dict) and "meta" in obj and "entries" in obj:
        pages = [{"pid": obj["meta"].get("schema","p-legacy"), "u": None, "eps": obj.get("entries", [])}]
    else:
        print(f"[uploader] {base}: format inconnu, ignoré.")
        return

    print(f"[uploader] {base}: {len(pages)} page(s)")

    for page in pages:
        pid = page.get("pid") or f"p-{stable_hash(json.dumps(page.get('u','')))}"
        redacted = redact_page(page)

        out_name = f"{os.path.splitext(base)[0]}__{pid}.cmds.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)
        if os.path.exists(out_path):
            print(f"[uploader] skip {out_name} (déjà présent)")
            continue

        result: List[Dict[str, Any]] = []
        ok = False
        for attempt in range(RETRIES):
            try:
                result = call_model_chat(redacted)
                ok = True
                break
            except Exception as e:
                print(f"[uploader] chat attempt {attempt+1}/{RETRIES} failed: {e}")
                backoff_sleep(attempt)

        if not ok:
            err_path = out_path + ".error"
            with open(err_path, "w", encoding="utf-8") as ef:
                ef.write("API error after retries\n")
            print(f"[uploader] FAILED: {out_name}")
            continue

        # Enforce stealth flags (ajouts/suppressions) après génération
        result = enforce_stealth(result)

        try:
            Draft202012Validator(OUTPUT_SCHEMA).validate(result)
        except Exception as e:
            err_path = out_path + ".schema.error"
            with open(err_path, "w", encoding="utf-8") as ef:
                ef.write(str(e))
            print(f"[uploader] SCHEMA ERROR: {out_name}")
            continue

        with open(out_path, "w", encoding="utf-8") as w:
            json.dump(result, w, ensure_ascii=False, indent=2)
        total_cmds = sum(len(x.get("tools", [])) for x in result)
        print(f"[uploader] OK: {out_name} ({len(result)} endpoints, {total_cmds} cmd(s))")

def main():
    files = []
    args = sys.argv[1:]
    if args:
        for a in args:
            if os.path.isdir(a):
                files.extend(sorted(glob.glob(os.path.join(a, "*.json"))))
            else:
                files.append(a)
    else:
        files = sorted(glob.glob(os.path.join(INPUT_DIR, "*.json")))
        if not files:
            files = sorted(glob.glob(os.path.join(INPUT_DIR, "*.json")))
        if not files:
            files = sorted(glob.glob(os.path.join(INPUT_DIR, "*.json")))
    if not files:
        print("[uploader] Rien à traiter. Placez vos JSON dans INPUT_DIR (reco).")
        sys.exit(0)

    for path in files:
        try:
            process_file(path)
        except Exception as e:
            print(f"[uploader] ERROR processing {path}: {e}")

if __name__ == "__main__":
    main()
