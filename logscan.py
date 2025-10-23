from mitmproxy import http
import json, os, re, base64, time, uuid, html as htmlmod
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional

# =========================
#   CONFIG / SORTIE
# =========================
OUT_DIR = os.environ.get("LOGSCAN_OUT", "reco")
API_MODE = True                 # ON: écrit pages[] avec IDs entiers (prêt pour GPT-4.1)
COMPACT_MODE = True             # ON: clés courtes optimisées tokens
MAX_TEXT_EXCERPT = int(os.environ.get("LOGSCAN_MAX_TEXT_EXCERPT", "2000"))
MAX_BIN_INLINE = int(os.environ.get("LOGSCAN_MAX_BIN_INLINE", "16384"))

OUT_FILE = None  # fixé au démarrage

def load_allowed_domains():
    urls_file = os.environ.get("URLS_FILE", "urls.txt")
    allowed = set()
    try:
        with open(urls_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parsed = urlparse(line)
                    if parsed.hostname:
                        allowed.add(parsed.hostname)
    except Exception as e:
        print(f"[logscan] ⚠ Impossible de charger {urls_file}: {e}")
    return allowed

ALLOWED_DOMAINS = load_allowed_domains()

# Mémoire du batch (brut normalisé par requête)
BATCH: List[Dict[str, Any]] = []
INFLIGHT: Dict[str, Dict[str, Any]] = {}
PAGE_MAP: Dict[str, str] = {}  # referer/top_url -> page_id
LAST_PAGE_ID: Optional[str] = None

# =========================
#   UTILS
# =========================
def safe_dict(d) -> Dict[str, Any]:
    try:
        return {str(k): str(v) for k, v in d.items()}
    except Exception:
        try:
            return dict(d)
        except Exception:
            return {}

def is_allowed(flow: http.HTTPFlow) -> bool:
    host = flow.request.host
    return host in ALLOWED_DOMAINS if ALLOWED_DOMAINS else True

def guess_params(flow: http.HTTPFlow) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    # Query (MultiDict)
    try:
        q = flow.request.query
        if hasattr(q, "get_all"):
            for k in q.keys():
                vals = q.get_all(k)
                out[str(k)] = vals[0] if len(vals) == 1 else vals
        else:
            qs = parse_qs(str(q), keep_blank_values=True)
            for k, v in qs.items():
                out[str(k)] = v[0] if isinstance(v, list) and len(v) == 1 else v
    except Exception:
        pass
    # Body
    ctype = (flow.request.headers.get("content-type") or "").lower()
    body_bytes = flow.request.content or b""
    if "application/json" in ctype:
        try:
            obj = flow.request.json()
            if isinstance(obj, dict):
                for k, v in obj.items(): out[str(k)] = v
        except Exception: pass
    elif "application/x-www-form-urlencoded" in ctype:
        try:
            body_str = body_bytes.decode("utf-8", errors="ignore")
            form = parse_qs(body_str, keep_blank_values=True)
            for k, v in form.items():
                out[str(k)] = v[0] if isinstance(v, list) and len(v) == 1 else v
        except Exception: pass
    elif "multipart/form-data" in ctype:
        out["__multipart__"] = True
    return out

def text_excerpt(b: Optional[bytes]) -> Optional[str]:
    if not b: return None
    try:
        s = b.decode("utf-8", errors="ignore")
        if len(s) > MAX_TEXT_EXCERPT: s = s[:MAX_TEXT_EXCERPT] + "…[truncated]"
        return s
    except Exception:
        return None

def body_repr_for_response(flow: http.HTTPFlow) -> Dict[str, Any]:
    body = flow.response.content or b""
    ctype = (flow.response.headers.get("content-type") or "").lower()
    if any(t in ctype for t in ["text/", "json", "xml", "javascript", "html"]) or body.startswith(b"{") or body.startswith(b"<"):
        return {"type": "text", "excerpt": text_excerpt(body)}
    if len(body) <= MAX_BIN_INLINE:
        return {"type": "binary", "base64": base64.b64encode(body).decode()}
    return {"type": "binary", "base64": None, "note": f"binary too large ({len(body)} bytes), not inlined"}

ERROR_KEYWORDS = [
    r"sql syntax", r"mysql", r"psql", r"postgres", r"sqlite", r"odbc",
    r"syntax error", r"unterminated string", r"exception", r"stack trace",
    r"warning: ", r"fatal error", r"line \d+"
]
def find_error_keywords(text: str) -> List[str]:
    if not text: return []
    low = text.lower(); hits=[]
    for pat in ERROR_KEYWORDS:
        try:
            if re.search(pat, low): hits.append(pat)
        except Exception: pass
    return hits

def list_set_cookies_headers(resp_headers_obj) -> List[str]:
    try:
        get_all = getattr(resp_headers_obj, "get_all", None)
        if callable(get_all): return [str(v) for v in get_all("Set-Cookie")]
    except Exception: pass
    values=[]
    try:
        for k, v in resp_headers_obj.items(multi=True):
            if str(k).lower()=="set-cookie": values.append(str(v))
        if values: return values
    except Exception: pass
    try:
        for k, v in resp_headers_obj.items():
            if str(k).lower()=="set-cookie":
                if isinstance(v, list): values.extend([str(x) for x in v])
                else: values.append(str(v))
    except Exception: pass
    return values

def response_contains_params(resp_text: Optional[str], params: Dict[str, Any]) -> List[str]:
    """
    Renvoie la liste des noms de paramètres dont la valeur apparaît (brut ou échappée) dans la réponse.
    """
    if not resp_text or not params:
        return []
    out = []
    unescaped = htmlmod.unescape(resp_text)
    for name, val in params.items():
        # Ne considérer que des scalaires textuels simples
        if isinstance(val, (list, dict)):
            continue
        sval = str(val)
        if not sval:
            continue
        # match brut
        if sval in resp_text or sval in unescaped:
            out.append(str(name))
            continue
        # match échappé rudimentaire (HTML)
        escaped = (
            sval.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;")
        )
        if escaped in resp_text:
            out.append(str(name))
    return out

def infer_auth_indicator(status: int, resp_headers: Dict[str, Any], resp_text_excerpt: Optional[str]) -> str:
    try:
        if status in (401,403): return "restricted"
        loc = None
        for k,v in resp_headers.items():
            if str(k).lower()=="location": loc=str(v); break
        if loc and ("login" in loc.lower() or "signin" in loc.lower()): return "restricted"
        cookies = list_set_cookies_headers(resp_headers)
        if any(("session" in c.lower() or "jwt" in c.lower() or "sid=" in c.lower()) for c in cookies): return "maybe_user"
    except Exception: pass
    return "none"

# =========================
#   HOOKS mitmproxy
# =========================
def load(l):
    global OUT_FILE
    os.makedirs(OUT_DIR, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    name = "ia_pages_" + ts + ".json" if API_MODE else "ia_batch_" + ts + ".json"
    OUT_FILE = os.path.join(OUT_DIR, name)
    print(f"[logscan] Sortie IA: {OUT_FILE}")
    if ALLOWED_DOMAINS:
        print(f"[logscan] Cibles: {', '.join(sorted(ALLOWED_DOMAINS))}")
    else:
        print("[logscan] ⚠ Aucune liste de domaines fournie (urls.txt). Tout sera capturé.")
    print("[logscan] Mode: API pages (ids entiers) + compact ON")

def request(flow: http.HTTPFlow):
    if not is_allowed(flow): return
    global LAST_PAGE_ID
    referer = flow.request.headers.get("Referer", None)
    page_id = None
    if not referer:
        page_id = f"p-{int(time.time()*1000)}"
        PAGE_MAP[flow.request.pretty_url] = page_id
        LAST_PAGE_ID = page_id
    else:
        page_id = PAGE_MAP.get(referer, LAST_PAGE_ID)

    entry = {
        "id": str(uuid.uuid4()),
        "page_id": page_id,
        "url": flow.request.pretty_url,
        "path": flow.request.path,  # path court utile pour l'IA
        "method": flow.request.method,
        "request_headers": safe_dict(flow.request.headers),
        "request_cookies": safe_dict(flow.request.cookies),
        "request_query": safe_dict(flow.request.query),
        "request_content_type": flow.request.headers.get("content-type", ""),
        "params": {},
        "referer": referer,
        "user_agent": flow.request.headers.get("User-Agent", None),
        "timestamp_start": getattr(flow.request, "timestamp_start", None),
    }

    # params fusionnés
    try: entry["params"] = guess_params(flow)
    except Exception: entry["params"] = {}

    INFLIGHT[flow.id] = entry

def response(flow: http.HTTPFlow):
    if not is_allowed(flow): return
    base = INFLIGHT.pop(flow.id, None)
    if base is None:
        referer = flow.request.headers.get("Referer", None)
        page_id = PAGE_MAP.get(referer, LAST_PAGE_ID)
        base = {
            "id": str(uuid.uuid4()),
            "page_id": page_id,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "method": flow.request.method,
            "request_headers": safe_dict(flow.request.headers),
            "request_cookies": safe_dict(flow.request.cookies),
            "request_query": safe_dict(flow.request.query),
            "request_content_type": flow.request.headers.get("content-type", ""),
            "params": guess_params(flow),
            "referer": referer,
            "user_agent": flow.request.headers.get("User-Agent", None),
            "timestamp_start": getattr(flow.request, "timestamp_start", None),
        }

    status = flow.response.status_code
    resp_headers_raw = flow.response.headers
    resp_headers = safe_dict(resp_headers_raw)
    ctype = (flow.response.headers.get("content-type") or "")
    body_info = body_repr_for_response(flow)
    excerpt = body_info.get("excerpt") if body_info.get("type")=="text" else None

    contains = response_contains_params(excerpt or "", base.get("params") or {})
    errors = find_error_keywords(excerpt or "")

    base.update({
        "status_code": status,
        "response_headers": resp_headers,
        "response_content_type": ctype,
        "response_body": body_info,
        "response_contains_param_values": contains,
        "location_header": resp_headers.get("Location") or resp_headers.get("location"),
        "set_cookies": list_set_cookies_headers(resp_headers_raw),
        "error_keywords": errors,
        "auth_indicator": infer_auth_indicator(status, resp_headers, excerpt),
        "timestamp_end": getattr(flow.response, "timestamp_end", None),
    })

    BATCH.append(base)

# ---------- Compactage + Grouping pour API ----------
def compact_entry(e: Dict[str, Any]) -> Dict[str, Any]:
    rb = e.get("response_body") or {}
    return {
        "m": e.get("method"),
        "p": e.get("path") or e.get("url"),
        "sc": e.get("status_code"),
        "ct": e.get("response_content_type"),
        "rb": {"t": rb.get("type"), "x": rb.get("excerpt")},
        "prms": e.get("params") or {},
        "x": e.get("response_contains_param_values") or [],
        "ek": e.get("error_keywords") or [],
        "ai": e.get("auth_indicator"),
        "loc": e.get("location_header"),
        "setc": e.get("set_cookies") or []
    }

def build_pages_api(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Regrouper par page_id
    pages: Dict[str, Dict[str, Any]] = {}
    top_url_by_pid: Dict[str, str] = {}

    # 1) collect urls candidates (top doc = sans Referer)
    for e in entries:
        pid = e.get("page_id") or "p-unknown"
        if pid not in pages:
            pages[pid] = {"pid": pid, "u": None, "eps_raw": []}
        pages[pid]["eps_raw"].append(e)
        if (e.get("referer") is None) and (pages[pid].get("u") is None):
            pages[pid]["u"] = e.get("url")

    # fallback: si pas de top doc, prendre la première url
    for pid, obj in pages.items():
        if obj.get("u") is None and obj["eps_raw"]:
            obj["u"] = obj["eps_raw"][0].get("url")

    # 2) compacter endpoints + donner i=0..N-1
    out_pages = []
    for pid, obj in pages.items():
        eps = []
        for e in obj["eps_raw"]:
            eps.append(compact_entry(e))
        # indexation
        for idx, ep in enumerate(eps):
            ep["i"] = idx
        out_pages.append({"pid": pid, "u": obj.get("u"), "eps": eps})

    # meta
    meta = {
        "schema": "page_batch_v1",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries_count": len(entries),
        "allowed_domains": sorted(list(ALLOWED_DOMAINS)) if ALLOWED_DOMAINS else None,
        "compact_keys": {
            "pid":"page_id","u":"page_url",
            "eps":"endpoints","i":"index",
            "m":"method","p":"path_or_url","sc":"status_code","ct":"content_type",
            "rb.t":"response_body.type","rb.x":"response_body.excerpt",
            "prms":"params(merged)","x":"reflected_param_names",
            "ek":"error_keywords","ai":"auth_indicator",
            "loc":"location_header","setc":"set_cookie_list"
        }
    }
    return {"meta": meta, "pages": out_pages}

def done():
    if not OUT_FILE:
        return
    try:
        os.makedirs(OUT_DIR, exist_ok=True)

        # NEW: flusher les entrées requête restées en vol (pas de réponse vue)
        if INFLIGHT:
            for _fid, base in list(INFLIGHT.items()):
                pending = dict(base)
                pending.update({
                    "status_code": None,
                    "response_headers": {},
                    "response_content_type": "",
                    "response_body": {"type": "text", "excerpt": None},
                    "response_contains_param_values": [],
                    "location_header": None,
                    "set_cookies": [],
                    "error_keywords": [],
                    "auth_indicator": "none",
                    "timestamp_end": None,
                })
                BATCH.append(pending)
            INFLIGHT.clear()

        if API_MODE:
            out_obj = build_pages_api(BATCH)
        else:
            # old batch (non groupé), conservé à titre rétro
            meta = {
                "schema": "flat_batch_v1",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "entries_count": len(BATCH),
                "allowed_domains": sorted(list(ALLOWED_DOMAINS)) if ALLOWED_DOMAINS else None,
            }
            out_obj = {"meta": meta, "entries": BATCH}

        with open(OUT_FILE, "w", encoding="utf-8") as f:
            json.dump(out_obj, f, ensure_ascii=False, indent=2)
        print(f"[logscan] ✅ Écrit {len(BATCH)} entrées dans {OUT_FILE}")
    except Exception as e:
        print(f"[logscan] ❌ Erreur écriture {OUT_FILE}: {e}")
