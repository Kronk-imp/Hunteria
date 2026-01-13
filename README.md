# HunterIA — Intelligent, stealthy web pentest orchestrator

**HunterIA** is a modular pipeline that combines a headless browser explorer, network capture, AI-driven command generation and controlled execution of detection tools.
The project’s goal is to reduce noise and false positives produced by traditional scanners by *targeting relevant endpoints* and *reusing existing mature tools* for detection rather than re-implementing their functionality.

---

## Key idea

Traditional automated scanners are often:

* not very *intelligent* about which endpoints deserve heavy testing, and
* very *noisy* (lots of requests, brute force, many false positives).

HunterIA focuses on:

* identifying *high-value endpoints* (forms, AJAX endpoints, reflected parameters, error messages, session indicators) using an intelligent exploration phase, and
* delegating detection to existing, battle-tested tools (sqlmap, dalfox, tplmap, etc.) with conservative, detection-only flags.

Why reuse existing tools? Because high-quality tools already exist and their authors invested huge amounts of time engineering detection features. It is far more effective to orchestrate those tools sensibly than to try to duplicate their capabilities inside a single monolithic scanner.

---

## What it does (pipeline)

1. **Explore** the target with a headless browser (Playwright) to mimic human interactions and surface relevant endpoints and dynamic behavior (`bot.py`).
2. **Capture** HTTP(S) traffic via mitmproxy and normalize captured requests/responses into a compact JSON format (`logscan.py`).
3. **Analyze** the captured data with an OpenAI model to produce a JSON of endpoints → recommended vulnerabilities → detection commands (`uploader.py`).
4. **(Optional) Execute** those detection commands in a controlled manner and archive logs (`exec_cmds.py`).

---

## Important notes / safety

* Generated commands are intended to be **detection-only**. The pipeline applies additional enforcement (stealth flags, removal of destructive options) before output.
* This project is for **ethical, legal use only** (authorized testing, labs, engagement with written permission).
* The project is **still in active development**. Some features may be incomplete or unstable; tests and improvements are ongoing.
* You **must** review generated commands before running them on real targets. 

---

## Dependencies

### System / tools (recommended)

These tools are used by the pipeline (AI suggests commands for them). Install only what you need and understand.

* `sqlmap` — automated SQL injection detection (detection-only flags used).
* `dalfox` — XSS detection and payload testing.
* `tplmap` — server-side template injection (SSTI) testing.
* `commix` — command injection testing (detection profile).
* `ssrfmap` — SSRF discovery (uses raw request files).
* `OpenRedireX` — open-redirect checks.
* `ppfuzz` — prototype pollution fuzzing (client-side).
* `xsrfprobe` — CSRF heuristics.

Install these tools from their upstream repos (GitHub). The project assumes they are in your `PATH`.

### Python / runtime

* Python >= 3.9
* pip packages:

  * `playwright`
  * `mitmproxy`
  * `openai`
  * `jsonschema`

Install example:

```bash
python -m pip install --upgrade pip
pip install playwright mitmproxy openai jsonschema
playwright install chromium
```

---

## Environment variables

* `OPENAI_API_KEY` — **required** to call the OpenAI API.
* Optional:

  * `OPENAI_MODEL` — model name (default set in `uploader.py`).
  * `INPUT_DIR`, `OUTPUT_DIR` — override directories used by `uploader.py`.
  * `MAX_CMDS_PER_EP`, `DEFAULT_STEALTH_DELAY`, etc. — see `uploader.py` top section for more tunables.

Set your OpenAI key in the shell before running:

```bash
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## Quick start

1. clone the repo:

```bash
git clone https://github.com/Kronk-imp/Hunteria
cd hunteria
```

2. prepare targets:

```bash
# put a single target per line (or a list of urls)
echo "http://10.10.246.87/login.php" > urls.txt
```

3. Usage:

```bash
#   ./hunteria                # run_scan.sh -> uploader.py (no execution)
#   ./hunteria --exec         # + excution of the commandes provides by AI
#   ./hunteria --no-wait      # skip waiting (faster but less sure)
#   ./hunteria --timeout 120  # controle the timeout in the pipeline (défaut: 90)
```

---

## Configuration highlights

* `uploader.py` contains a whitelist of allowed vulnerabilities and tools. The AI output is validated against a JSON schema and then post-processed by `enforce_stealth()` to add conservative flags such as `--threads=1`, `--delay 2`, `--random-agent`, and to remove destructive flags (e.g., sqlmap `--dump`).
* `bot.py` uses `useragents.txt` to randomize UA and includes logic to avoid clicking destructive buttons (logout/delete) and to not navigate to cross-domain links.

---

## Output locations

* Raw capture / pages: `reco/ia_pages_<timestamp>.json`
* AI-generated commands: `reco/triage/<base>__<pid>.cmds.json`
* Execution artifacts (plans, logs, summary): `reco/exec/`

---

## Tested scenarios

So far the pipeline has been tested on the **OWASP Juice Shop** room (TryHackMe). Results were promising:

* The endpoint selection was effective at surfacing relevant endpoints (login, contact forms, API endpoints).
* The generated commands and chosen tools were judged to be appropriate and useful for detection in that environment.

This is not comprehensive testing — run in controlled labs and carefully verify outputs before using on real targets.

---

## Development status

* Active development: bugs and missing features expected.
* Contributions, bug reports and PRs are welcome.
* Please review generated commands before executing 

---

## Example outputs / behavior

* `logscan.py` produces compact page batches (`page_batch_v1`) containing endpoints with reflected params, error keywords, cookies, status codes.
* `uploader.py` sends redacted JSON to the configured OpenAI model and expects a strict JSON array as output: `[{ "i": <index>, "vulns": ["sqli"], "tools": [{"tool":"sqlmap","cmd":"..."}] }, ...]`.
* `exec_cmds.py` parses the `.cmds.json` files and can either write a full run plan or execute commands with per-command timeouts and logs.

---

## Author

Kronk-imp
