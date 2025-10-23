#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, json, os, re, shlex, subprocess, time
from pathlib import Path
from typing import List, Dict, Any

ROOT = Path(__file__).resolve().parent
DEFAULT_SRC = ROOT / "reco" / "triage"
DEFAULT_OUT = ROOT / "reco" / "exec"

def eprint(*a): print(*a, flush=True)

def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _guess_tool_from_cmd(cmd: str) -> str:
    first = shlex.split(cmd)[0] if cmd.strip() else ""
    return Path(first).name if first else "cmd"

def _extract_cmds_flex(obj: Any) -> List[Dict[str, str]]:
    """
    Tolère plusieurs schémas possibles:
      A) [ { "tools":[{"tool":"sqlmap", "cmd":"..."}, ...], ... }, ... ]
      B) { "commands": ["...", "..."] }  ou  { "commands":[{"cmd":"..."}] }
      C) [ "cmd1 ...", "cmd2 ..." ]
      D) Fallback: regex sur toutes les clés "cmd": "..."
    Retourne: [{"tool": <str>, "cmd": <str>}, ...]
    """
    out = []

    # A) liste d'objets avec "tools"
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and "tools" in item and isinstance(item["tools"], list):
                for t in item["tools"]:
                    if isinstance(t, dict) and "cmd" in t and t["cmd"]:
                        out.append({"tool": t.get("tool") or _guess_tool_from_cmd(t["cmd"]), "cmd": t["cmd"]})
        if out:
            return out

    # B) dict avec "commands"
    if isinstance(obj, dict) and "commands" in obj:
        cmds = obj["commands"]
        if isinstance(cmds, list):
            for c in cmds:
                if isinstance(c, str) and c.strip():
                    out.append({"tool": _guess_tool_from_cmd(c), "cmd": c})
                elif isinstance(c, dict) and "cmd" in c and c["cmd"]:
                    out.append({"tool": c.get("tool") or _guess_tool_from_cmd(c["cmd"]), "cmd": c["cmd"]})
        if out:
            return out

    # C) liste brute de strings
    if isinstance(obj, list):
        raw = [x for x in obj if isinstance(x, str) and x.strip()]
        if raw:
            return [{"tool": _guess_tool_from_cmd(c), "cmd": c} for c in raw]

    # D) regex fallback sur "cmd": "..."
    text = json.dumps(obj, ensure_ascii=False)
    for m in re.finditer(r'"cmd"\s*:\s*"([^"]+)"', text):
        c = m.group(1)
        if c.strip():
            out.append({"tool": _guess_tool_from_cmd(c), "cmd": c})
    return out

def find_cmd_files(src_dir: Path, glob_pat: str) -> List[Path]:
    files = sorted(src_dir.glob(glob_pat), key=lambda p: p.stat().st_mtime)
    return files

def run_cmd(cmd: str, timeout: int, cwd: Path, log_path: Path) -> int:
    with open(log_path, "w", encoding="utf-8") as w:
        w.write(f"$ {cmd}\n\n")
        w.flush()
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=w, stderr=subprocess.STDOUT, cwd=str(cwd))
            try:
                return proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                w.write("\n[timeout] Command exceeded the time limit.\n")
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                return 124
        except Exception as e:
            w.write(f"\n[error] {e}\n")
            return 1

def main():
    ap = argparse.ArgumentParser(description="Exécuter les commandes générées par l'IA et archiver les sorties.")
    ap.add_argument("--src-dir", default=str(DEFAULT_SRC), help="Répertoire contenant les *.cmds.json (défaut: reco/triage)")
    ap.add_argument("--glob", default="*.cmds.json", help="Motif des fichiers de commandes (défaut: *.cmds.json)")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT), help="Répertoire de sortie des logs/plan (défaut: reco/exec)")
    ap.add_argument("--cmd-timeout", type=int, default=900, help="Timeout par commande en secondes (défaut: 900)")
    ap.add_argument("--max", type=int, default=0, help="Limiter le nombre total de commandes exécutées (0 = illimité)")
    ap.add_argument("--dry-run", action="store_true", help="N'exécute pas, écrit seulement le plan")
    args = ap.parse_args()

    src = Path(args.src_dir); out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)

    files = find_cmd_files(src, args.glob)
    if not files:
        eprint("[exec_cmds] Aucun fichier correspondant.")
        return

    all_cmds = []
    for f in files:
        try:
            data = load_json(f)
            cmds = _extract_cmds_flex(data)
            for c in cmds:
                all_cmds.append({"file": f.name, "tool": c["tool"], "cmd": c["cmd"]})
        except Exception as e:
            eprint(f"[exec_cmds] Erreur lecture {f.name}: {e}")

    if not all_cmds:
        eprint("[exec_cmds] Aucun 'cmd' détecté dans les JSON.")
        return

    ts = time.strftime("%Y-%m-%d_%H%M%S")
    plan_path = out / f"plan_{ts}.json"
    with open(plan_path, "w", encoding="utf-8") as w:
        json.dump(all_cmds, w, ensure_ascii=False, indent=2)
    eprint(f"[exec_cmds] Plan écrit: {plan_path}")

    # Résumé CSV
    csv_path = out / f"summary_{ts}.csv"
    with open(csv_path, "w", encoding="utf-8") as c:
        c.write("idx;tool;file;status;log\n")

        executed = 0
        for i, rec in enumerate(all_cmds, 1):
            if args.max and executed >= args.max:
                break

            tool = rec["tool"] or "cmd"
            base = files[0].stem if files else "cmds"
            safe_file = rec["file"].replace(".json", "").replace("/", "_")
            log_path = out / f"{ts}_{i:03d}_{tool}_{safe_file}.log"
            eprint(f"[exec_cmds] ({i}/{len(all_cmds)}) {tool} -> {log_path.name}")
            eprint(f"[exec_cmds] CMD: {rec['cmd']}")

            if args.dry_run:
                with open(log_path, "w", encoding="utf-8") as w:
                    w.write(f"# DRY-RUN\n# {rec['cmd']}\n")
                status = 0
            else:
                status = run_cmd(rec["cmd"], timeout=args.cmd_timeout, cwd=ROOT, log_path=log_path)

            c.write(f"{i};{tool};{rec['file']};{status};{log_path.name}\n")
            c.flush()
            executed += 1

    eprint(f"[exec_cmds] Terminé. Logs dans: {out}")

if __name__ == "__main__":
    main()
