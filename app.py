"""
app.py  --  Wazuh Correlation Agent  --  Analyst UI
Run:
  python3 app.py
  python3 app.py --port 5000 --log-file /var/log/wazuh-agent/investigations.log

Open http://localhost:5000 in any browser.
"""
import os, sys, re, json, queue, threading, time, logging, argparse
from datetime import datetime
from pathlib import Path
from collections import OrderedDict
from flask import Flask, Response, request, render_template_string, jsonify
from flask_cors import CORS

# ── Bootstrap ─────────────────────────────────────────────────────────────────
def _load_env(p=".env"):
    if Path(p).exists():
        for line in Path(p).read_text().splitlines():
            if line.strip() and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_load_env()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correlate as ag

app  = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("app")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3")
UI_PORT      = int(os.getenv("UI_PORT", 5000))


# ── Shared state ──────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.lock      = threading.Lock()   # one investigation at a time
        self.stop      = threading.Event()
        self.log_file  = ""
        self.sched_cfg = {"enabled": False, "interval_hours": 8,
                          "severity": 7, "hours": 24, "agent": ""}
        self.sched_wake = threading.Event()
        # Report history — persisted to disk so restarts don't lose it
        self.history    = OrderedDict()
        self.hist_lock  = threading.Lock()
        self.hist_file  = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "investigations.json")
        self._load_history()

    def _load_history(self):
        try:
            if Path(self.hist_file).exists():
                data = json.loads(Path(self.hist_file).read_text())
                for item in data:
                    self.history[item["id"]] = item
                log.info("Loaded %d investigations from history", len(self.history))
        except Exception as e:
            log.warning("Could not load history: %s", e)

    def _save_history(self):
        try:
            items = list(self.history.values())[-50:]  # keep last 50
            Path(self.hist_file).write_text(json.dumps(items, indent=2))
        except Exception as e:
            log.warning("Could not save history: %s", e)

ST = State()


# ── Natural language parser ───────────────────────────────────────────────────
def parse_nl(text):
    """
    Parse a natural language query into action parameters.
    Returns a dict with:
      - intent:   "investigate" | "hunt_ioc" | "hunt_ttp"
      - For investigate: severity, hours, agent, summary
      - For hunt:        query, days, agent, hunt_type, summary
    """
    t   = text.lower().strip()
    out = {
        "intent":   "investigate",
        "severity": int(os.getenv("MIN_SEVERITY",    7)),
        "hours":    int(os.getenv("LOOK_BACK_HOURS", 24)),
        "agent":    "",
        "notes":    [],
    }

    # ── Detect hunt intent ────────────────────────────────────────────────────
    # IOC patterns: IP, hash, CVE, domain-like strings
    import re as _re
    _IP   = _re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    _HASH = _re.compile(r"[0-9a-fA-F]{32,64}")
    _CVE  = _re.compile(r"cve-\d{4}-\d+", _re.I)

    # Hunt trigger words
    HUNT_WORDS = ["search", "find", "hunt", "look for", "scan for",
                  "detect", "any sign of", "appeared", "activities",
                  "across all", "across agents", "in the logs", "occurrences of"]
    IOC_WORDS  = ["ip", "address", "hash", "domain", "cve", "indicator",
                  "ioc", "malicious ip", "suspicious ip"]
    TTP_WORDS  = ["pass the hash", "mimikatz", "lateral movement", "psexec",
                  "scheduled task", "process injection", "powershell abuse",
                  "credential dump", "wmi", "persistence", "reconnaissance",
                  "port scan", "malware", "ransomware", "technique", "tactic",
                  "ttp", "mitre"]

    is_hunt_trigger = any(w in t for w in HUNT_WORDS)
    is_ioc_content  = (_IP.search(text) or _HASH.search(text) or
                       _CVE.search(t)   or any(w in t for w in IOC_WORDS))
    is_ttp_content  = any(w in t for w in TTP_WORDS)

    # Triage intent — "what should I look at first", "triage", prioritize
    TRIAGE_WORDS = ["triage", "what should i", "what needs", "look at first",
                    "prioriti", "what to investigate", "rundown of alerts",
                    "overview of alerts", "summarize alerts", "summarise alerts",
                    "where to start", "what is important", "what's important"]
    if any(w in t for w in TRIAGE_WORDS):
        out["intent"] = "triage"
        m = _re.search(r"(\d+)\s*(day|days|d\b)", t)
        if m:
            out["hours"] = int(m.group(1)) * 24
        else:
            m = _re.search(r"(\d+)\s*(h\b|hr\b|hour|hours)", t)
            if m:          out["hours"] = int(m.group(1))
            elif "week"  in t: out["hours"] = 168
            elif "today" in t: out["hours"] = 24
            else:              out["hours"] = 24
        am = _re.search(r"\bagent\s+(?:id\s+)?(\d{1,3})\b", t)
        if am: out["agent"] = am.group(1).zfill(3)
        period = (f"last {out['hours']//24}d" if out["hours"]>=24 and out["hours"]%24==0
                  else f"last {out['hours']}h")
        out["notes"] = [period]
        if out["agent"]: out["notes"].append(f"agent {out['agent']}")
        out["summary"] = "  |  ".join(out["notes"])
        return out

    # Threat-category intent — high-level analyst questions.
    # These map to bundles of detection patterns (a whole attack class).
    THREAT_PATTERNS = {
        "exfiltration": ["exfiltrat", "data exfil", "data leav", "data steal",
                         "data loss", "leaking data", "stealing data"],
        "rce":          ["remote code execution", "remote command", "rce",
                         "code execution", "remote execution"],
        "privesc":      ["privilege escalation", "privesc", "escalat",
                         "elevation", "gained admin", "became admin"],
        "persistence":  ["persistence", "persist", "foothold", "backdoor"],
        "credential_access": ["credential access", "credential theft",
                              "stolen credential", "credential harvest",
                              "dumping credential", "stealing password"],
        "lateral":      ["lateral movement", "moving laterally", "pivot",
                         "spreading across", "moving between"],
        "defense_evasion": ["defense evasion", "evading", "evasion",
                            "covering tracks", "hiding", "anti-forensic"],
        "critical":     ["critical alert", "urgent attention", "require attention",
                         "need attention", "most severe", "highest severity",
                         "what should i", "what needs", "top priority",
                         "requires urgent", "most important"],
    }
    threat_cat = None
    for cat, patterns in THREAT_PATTERNS.items():
        if any(p in t for p in patterns):
            threat_cat = cat
            break

    if threat_cat:
        out["intent"]       = "threat_category"
        out["threat_cat"]   = threat_cat
        # time: reuse the investigate-style hour parsing below by jumping there
        m = _re.search(r"(\d+)\s*(day|days|d\b)", t)
        if m:
            out["hours"] = int(m.group(1)) * 24
        else:
            m = _re.search(r"(\d+)\s*(h\b|hr\b|hour|hours)", t)
            if m:          out["hours"] = int(m.group(1))
            elif "week"  in t: out["hours"] = 168
            elif "today" in t: out["hours"] = 24
            else:              out["hours"] = 24
        # Extract agent if mentioned
        am = _re.search(r"\bagent\s+(?:id\s+)?(\d{1,3})\b", t)
        if am:
            out["agent"] = am.group(1).zfill(3)
        period = (f"last {out['hours']//24}d" if out["hours"]>=24 and out["hours"]%24==0
                  else f"last {out['hours']}h")
        out["notes"] = [period]
        if out["agent"]:
            out["notes"].append(f"agent {out['agent']}")
        out["summary"] = "  |  ".join(out["notes"])
        return out

    # Inventory intent — "packages/ports/processes/files on agent X"
    # Includes fuzzy matching so common typos (pacakges, proceses) still resolve.
    import difflib as _difflib
    INV_MAP = {
        "packages":  ["package", "packages", "installed software", "software"],
        "ports":     ["port", "ports", "listening", "open port"],
        "processes": ["process", "processes", "running process", "running processes"],
        "files":     ["file change", "files changed", "file integrity",
                      "fim", "modified files", "changed files"],
    }
    inv_kind = None
    # 1. Exact substring match first
    for kind, words in INV_MAP.items():
        if any(w in t for w in words):
            inv_kind = kind
            break
    # 2. Fuzzy match on individual words (catches typos like "pacakges")
    if not inv_kind:
        canonical = {"package": "packages", "packages": "packages",
                     "port": "ports", "ports": "ports",
                     "process": "processes", "processes": "processes",
                     "file": "files", "files": "files"}
        for word in t.split():
            match = _difflib.get_close_matches(word, canonical.keys(),
                                               n=1, cutoff=0.8)
            if match:
                inv_kind = canonical[match[0]]
                break

    if inv_kind:
        out["intent"]    = "inventory"
        out["inv_kind"]  = inv_kind
        out["only_suspicious"] = any(w in t for w in
            ["suspicious", "malicious", "flagged", "dangerous", "unusual"])
    elif is_ioc_content and (is_hunt_trigger or not is_ttp_content):
        out["intent"] = "hunt_ioc"
    elif is_ttp_content and is_hunt_trigger:
        out["intent"] = "hunt_ttp"
    elif is_hunt_trigger and not is_ioc_content and not is_ttp_content:
        out["intent"] = "hunt_ttp"

    # ── Extract agent (common to all intents) ─────────────────────────────────
    m = _re.search(r"\bagent\s+(?:id\s+)?(\d{1,3})\b", t)
    if m:
        out["agent"] = m.group(1).zfill(3)
        out["notes"].append(f"agent {out['agent']}")
    elif _re.search(r"\ball\s+agents?\b|\bevery\s+agent\b", t):
        out["notes"].append("all agents")

    if out["intent"] == "inventory":
        if out.get("only_suspicious"):
            out["notes"].append(f"suspicious {out['inv_kind']} only")
        else:
            out["notes"].append(out["inv_kind"])
        if out["agent"]:
            out["notes"].append(f"agent {out['agent']}")
        else:
            out["notes"].append("NO AGENT — required")
        out["summary"] = "  |  ".join(out["notes"])
        return out

    if out["intent"] in ("hunt_ioc", "hunt_ttp"):
        # Extract days for hunt (default 7)
        m = _re.search(r"(\d+)\s*hours?\b", t)
        if m:
            # hours → round up to at least 1 day for the date range
            hrs = int(m.group(1))
            out["days"] = max(1, round(hrs / 24))
        else:
            m = _re.search(r"(\d+)\s*days?\b", t)
            if m:
                out["days"] = int(m.group(1))
            elif "week" in t:
                out["days"] = 7
            elif "month" in t:
                out["days"] = 30
            else:
                out["days"] = 7

        # Extract the core hunt query — strip trigger/time phrases using
        # WORD BOUNDARIES so we never eat letters inside real words
        # (e.g. "has" must not match inside "hash").
        query = text
        strip_phrases = [
            r"\bsearch for\b", r"\bhunt for\b", r"\bhunt\b",
            r"\blook for\b", r"\bscan for\b", r"\bsearch\b",
            r"\bdetect\b", r"\bany sign of\b", r"\bshow me\b",
            r"\bcheck if\b", r"\bcheck for\b", r"\bfind\b",
            r"\bappeared\b", r"\bacross all agents\b",
            r"\bacross agents\b", r"\bin the logs\b",
            r"\bduring\b", r"\boccou?red\b", r"\boccurred\b",
            r"\bthe last\b", r"\blast\b", r"\bpast\b",
            r"\bthis week\b", r"\bthis month\b",
            r"\d+\s*hours?\b", r"\d+\s*days?\b",
            r"\bweek\b", r"\bmonth\b",
                    r"\bactivities\b", r"\bactivity\b", r"\boccurrences? of\b",
            r"\bevents?\b", r"\blogs?\b", r"\balerts?\b",
        ]
        if out["agent"]:
            strip_phrases.append(rf"\bagent\s+(?:id\s+)?{out['agent'].lstrip('0') or '0'}\b")
            strip_phrases.append(rf"\bagent\s+(?:id\s+)?{out['agent']}\b")
        for pat in strip_phrases:
            query = _re.sub(pat, " ", query, flags=_re.I)
        # Collapse whitespace and trim stray punctuation
        query = _re.sub(r"\s+", " ", query).strip(" ?,.-")
        out["query"]      = query or text
        out["hunt_type"]  = "ioc" if out["intent"] == "hunt_ioc" else "ttp"
        out["notes"].append(f"hunt: {out['query'][:40]}")
        out["notes"].append(f"last {out['days']}d")
    else:
        # ── Investigate parameters ────────────────────────────────────────────
        # Days first (e.g. "last 7 days"), then hours, then named periods.
        m = _re.search(r"(\d+)\s*(day|days|d\b)", t)
        if m:
            out["hours"] = int(m.group(1)) * 24
        else:
            m = _re.search(r"(\d+)\s*(h\b|hr\b|hour|hours)", t)
            if m:
                out["hours"] = int(m.group(1))
            elif "week"  in t: out["hours"] = 168
            elif "month" in t: out["hours"] = 720
            elif "today" in t: out["hours"] = 24
            elif _re.search(r"last\s+hour|past\s+hour|this\s+hour", t):
                out["hours"] = 1
        # Show in a friendly unit
        if out["hours"] >= 24 and out["hours"] % 24 == 0:
            out["notes"].append(f"last {out['hours']//24}d")
        else:
            out["notes"].append(f"last {out['hours']}h")

        m = _re.search(r"(?:severity|level)\s*(\d+)", t)
        if m:
            out["severity"] = int(m.group(1))
        else:
            if   "critical" in t: out["severity"] = 12
            elif "high"     in t: out["severity"] = 10
            elif "medium"   in t: out["severity"] = 7
            elif _re.search(r"\blow\b|\ball\b|\beverything\b|\bany\b", t):
                out["severity"] = 3
        out["notes"].append(f"severity >= {out['severity']}")

    out["summary"] = "  |  ".join(out["notes"])
    return out

# ── Investigation runner ──────────────────────────────────────────────────────
def _run(prompt, severity, hours, agent, q, run_id=None):
    """Run investigation, stream output to queue q, save to history."""
    import builtins
    real_print = builtins.print
    parts = []

    def _emit(text):
        q.put(text)
        parts.append(text)

    def _fake_print(*args, end="\n", flush=False, **kw):
        _emit(" ".join(str(a) for a in args) + end)

    builtins.print = _fake_print
    started = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        # If the UI provided explicit parameters (always the case when analyst
        # clicks "Run this" or fills the form), use them directly.
        # Only fall back to run_from_prompt when called with prompt only and
        # no explicit overrides — which does not happen from the UI.
        ag.run(severity=severity, hours=hours,
               agent_id=agent if agent else None)
        status = "completed"
    except Exception as e:
        _emit(f"\n[ERROR] {type(e).__name__}: {e}\n")
        status = "error"
    finally:
        builtins.print = real_print
        q.put("__DONE__")

    report = "".join(parts)

    # If the analyst hit Stop, mark it stopped and discard the partial report
    if ST.stop.is_set() or ag.STOP_FLAG.is_set():
        status = "stopped"
        report = "[Investigation stopped by user]"

    # Save to history
    if run_id:
        with ST.hist_lock:
            if run_id in ST.history:
                ST.history[run_id]["status"] = status
                ST.history[run_id]["report"] = report
                ST.history[run_id]["ended"]  = datetime.now().strftime("%H:%M")
            while len(ST.history) > 50:
                ST.history.popitem(last=False)
            ST._save_history()

    # Write to log file
    if ST.log_file:
        try:
            with open(ST.log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Run : {started} | "
                        f"{prompt[:80] if prompt else f'sev={severity} hrs={hours} agent={agent or chr(34)+chr(34)}'}\n")
                f.write(f"{'='*60}\n")
                f.write(report)
                f.write("\n")
        except Exception as e:
            log.warning("Log write failed: %s", e)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/parse", methods=["POST"])
def parse_route():
    result = parse_nl(request.get_json().get("text", ""))
    return jsonify(result)


@app.route("/stream")
def stream():
    severity = int(request.args.get("severity", 7))
    hours    = int(request.args.get("hours", 24))
    agent    = request.args.get("agent", "").strip()
    prompt   = request.args.get("prompt", "").strip()

    if not ST.lock.acquire(blocking=False):
        def busy():
            yield "data: [An investigation is already running. Wait for it to finish.]\n\n"
            yield "data: __DONE__\n\n"
        return Response(busy(), mimetype="text/event-stream")

    ST.stop.clear()
    ag.STOP_FLAG.clear()  # reset from any previous stop

    # Create history entry
    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    label   = prompt[:60] if prompt else f"sev={severity} hrs={hours} agent={agent or 'all'}"
    with ST.hist_lock:
        ST.history[run_id] = {
            "id":      run_id,
            "label":   label,
            "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "ended":   None,
            "status":  "running",
            "report":  "",
        }

    q = queue.Queue()
    t = threading.Thread(target=_run,
                         args=(prompt, severity, hours, agent, q, run_id),
                         daemon=True)
    t.start()

    def generate():
        try:
            while True:
                try:
                    # Wait up to 30s for a chunk, then send a keepalive comment
                    # so the browser does not drop the SSE connection.
                    # Total investigation can run for hours — no overall timeout.
                    chunk = q.get(timeout=30)
                except queue.Empty:
                    # Send SSE comment (ignored by browser, keeps connection alive)
                    yield ": keepalive\n\n"
                    continue
                if chunk == "__DONE__":
                    yield "data: __DONE__\n\n"
                    break
                for line in chunk.splitlines(keepends=True):
                    yield f"data: {line}\n\n"
        finally:
            ST.lock.release()

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/stop", methods=["POST"])
def stop():
    ST.stop.set()
    ag.STOP_FLAG.set()   # interrupt the LLM streaming loop in correlate.py
    return {"ok": True}


@app.route("/history")
def history():
    with ST.hist_lock:
        items = [{"id": v["id"], "label": v["label"],
                  "started": v["started"], "ended": v["ended"],
                  "status": v["status"],
                  "report": v.get("report", "")}   # needed for sidebar copy button
                 for v in reversed(list(ST.history.values()))]
    return jsonify(items)


@app.route("/history/<run_id>", methods=["GET"])
def get_report(run_id):
    with ST.hist_lock:
        item = ST.history.get(run_id)
    if not item:
        return jsonify({"error": "not found"}), 404
    return jsonify(item)


@app.route("/history/<run_id>", methods=["DELETE"])
def delete_report(run_id):
    with ST.hist_lock:
        if run_id not in ST.history:
            return jsonify({"error": "not found"}), 404
        del ST.history[run_id]
        try:
            import json as _json
            with open(ST.hist_file, "w", encoding="utf-8") as f:
                _json.dump(list(ST.history.values()), f,
                           ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning("History save after delete failed: %s", e)
    return jsonify({"ok": True})


@app.route("/hunt_debug", methods=["GET"])
def hunt_debug():
    """Diagnostic: dump a real event so we can see actual field names + values."""
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    since = (_dt.now(_tz.utc) - _td(days=30)).isoformat()

    out = {"since": since}

    # 1. Grab one real event and show its full structure
    try:
        sample = ag.ix_search({"range":{"timestamp":{"gte":since}}}, size=3)
        hits = sample.get("hits", [])
        out["total_30d"] = sample.get("total", 0)
        if hits:
            # Show top-level keys and the rule sub-object
            doc = hits[0]
            out["top_level_keys"] = sorted(doc.keys())
            out["rule_object"]    = doc.get("rule", "NO rule KEY")
            out["has_full_log"]   = "full_log" in doc
            out["full_log_sample"]= str(doc.get("full_log", "MISSING"))[:200]
            # Show all 3 descriptions
            out["sample_descriptions"] = [
                h.get("rule", {}).get("description", "?") for h in hits
            ]
    except Exception as e:
        out["sample_error"] = str(e)

    # 2. Test a term that DEFINITELY exists (from the data: "Powershell")
    term = (request.args.get("q") or "powershell").strip()
    out["term"] = term
    tests = {
        "match_description":  {"match":{"rule.description":term}},
        "match_desc_cap":     {"match":{"rule.description":term.capitalize()}},
        "wildcard_desc_lc":   {"wildcard":{"rule.description":{"value":f"*{term.lower()}*"}}},
        "wildcard_desc_kw":   {"wildcard":{"rule.description.keyword":{"value":f"*{term}*"}}},
        "match_phrase_desc":  {"match_phrase":{"rule.description":term}},
        "query_string_all":   {"query_string":{"query":term}},
    }
    out["counts"] = {}
    for name, qclause in tests.items():
        q = {"bool":{"must":[{"range":{"timestamp":{"gte":since}}}, qclause]}}
        try:
            r = ag.ix_agg(q, {"t":{"value_count":{"field":"rule.level"}}})
            out["counts"][name] = r.get("t",{}).get("value",0)
        except Exception as e:
            out["counts"][name] = f"ERR: {str(e)[:80]}"

    return jsonify(out)


@app.route("/inventory", methods=["POST"])
def inventory_route():
    data  = request.get_json() or {}
    kind  = (data.get("kind") or "").strip()
    agent = (data.get("agent") or "").strip()
    only_sus = bool(data.get("only_suspicious", False))
    if not kind:
        return jsonify({"error": "Missing inventory kind"}), 400
    if not agent:
        return jsonify({"error": "Inventory queries require an agent ID"}), 400
    try:
        return jsonify(ag.inventory(kind, agent, only_suspicious=only_sus))
    except Exception as e:
        log.exception("Inventory error")
        return jsonify({"error": str(e)}), 500


@app.route("/triage", methods=["POST"])
def triage_route():
    data     = request.get_json() or {}
    hours    = int(data.get("hours", 24))
    agent_id = (data.get("agent") or "").strip() or None
    try:
        result = ag.triage(hours=hours, agent_id=agent_id)
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = _triage_to_text(result)
        with ST.hist_lock:
            ST.history[run_id] = {
                "id": run_id, "label": f"TRIAGE: last {hours}h",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "ended":   datetime.now().strftime("%H:%M"),
                "status":  "completed", "report": report,
            }
            ST._save_history()
        result["run_id"] = run_id
        return jsonify(result)
    except Exception as e:
        log.exception("Triage error")
        return jsonify({"error": str(e)}), 500


def _triage_to_text(d):
    if d.get("error"): return f"TRIAGE\nError: {d['error']}"
    lines = [f"ALERT TRIAGE — last {d['hours']}h",
             f"{d['total']} alerts grouped into {d['situations']} situations", ""]
    for bucket, title in [("urgent","URGENT — investigate now"),
                          ("review","REVIEW — needs a look"),
                          ("routine","ROUTINE / LIKELY NOISE")]:
        items = d.get(bucket, [])
        if not items: continue
        lines.append(f"{title} ({len(items)})")
        for s in items:
            agents = ", ".join(s["agents"][:3])
            tac    = ", ".join(s["tactics"][:3]) if s["tactics"] else "no tactic"
            lines.append(f"- [{s['max_level']}] {s['group']}  "
                         f"({s['count']} events, {agents})  [{tac}]")
            if s.get("reason"):
                lines.append(f"    Why: {s['reason']}")
            if s.get("focus"):
                lines.append(f"    Look at: {'; '.join(s['focus'])}")
            if s.get("action"):
                lines.append(f"    Action: {s['action']}")
        lines.append("")
    return "\n".join(lines)


@app.route("/threat", methods=["POST"])
def threat_route():
    data     = request.get_json() or {}
    category = (data.get("category") or "").strip()
    hours    = int(data.get("hours", 24))
    agent_id = (data.get("agent") or "").strip() or None
    if not category:
        return jsonify({"error": "Missing threat category"}), 400
    try:
        result = ag.threat_hunt(category, hours=hours, agent_id=agent_id)
        # Save to history
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = _threat_to_text(result, hours)
        with ST.hist_lock:
            ST.history[run_id] = {
                "id": run_id, "label": f"THREAT: {result.get('label', category)}",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "ended":   datetime.now().strftime("%H:%M"),
                "status":  "completed", "report": report,
            }
            ST._save_history()
        result["run_id"] = run_id
        return jsonify(result)
    except Exception as e:
        log.exception("Threat hunt error")
        return jsonify({"error": str(e)}), 500


def _threat_to_text(d, hours):
    if d.get("error"):
        return f"THREAT HUNT\nError: {d['error']}"
    lines = [f"THREAT HUNT: {d.get('label','?')}",
             f"Period: last {hours}h  |  Matches: {d.get('total',0)}"]
    if d.get("max_sev"): lines.append(f"Max severity: {d['max_sev']}")
    if d.get("tactics"): lines.append(f"MITRE tactics: {', '.join(d['tactics'])}")
    lines.append("")
    if d.get("total",0) == 0:
        lines.append("No matching activity detected.")
        return "\n".join(lines)
    if d.get("by_agent"):
        lines.append("AFFECTED AGENTS")
        for b in d["by_agent"]:
            nm = (b.get("name",{}).get("buckets",[{}]) or [{}])
            nm = nm[0].get("key", b["key"]) if nm else b["key"]
            lines.append(f"- {nm}: {b['doc_count']} events")
        lines.append("")
    if d.get("by_rule"):
        lines.append("TOP MATCHED RULES")
        for b in d["by_rule"]:
            lines.append(f"- {b['key']}  ({b['doc_count']})")
        lines.append("")
    if d.get("samples"):
        lines.append("HIGHEST-SEVERITY EVENTS")
        for s in d["samples"][:10]:
            ts = (s.get("timestamp","") or "")[:19].replace("T"," ")
            ag_ = (s.get("agent",{}) or {}).get("name","?")
            rd = (s.get("rule",{}) or {}).get("description","")
            lv = (s.get("rule",{}) or {}).get("level","")
            lines.append(f"- {ts}  {ag_}  [{lv}]  {rd}")
    return "\n".join(lines)


@app.route("/hunt", methods=["POST"])
def hunt_route():
    data      = request.get_json() or {}
    query     = (data.get("query") or "").strip()
    days      = int(data.get("days", 7))
    agent_id  = (data.get("agent") or "").strip() or None
    hunt_type = data.get("type", "auto")
    if not query:
        return jsonify({"error": "Empty query"}), 400
    try:
        result = ag.hunt(query, days=days, agent_id=agent_id, hunt_type=hunt_type)

        # Save hunt to history as a text report
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = _hunt_to_text(result, query, days)
        with ST.hist_lock:
            ST.history[run_id] = {
                "id":      run_id,
                "label":   f"HUNT: {query[:40]}",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "ended":   datetime.now().strftime("%H:%M"),
                "status":  "completed",
                "report":  report,
            }
            ST._save_history()
        result["run_id"] = run_id
        return jsonify(result)
    except Exception as e:
        log.exception("Hunt error")
        return jsonify({"error": str(e)}), 500


def _hunt_to_text(d, query, days):
    """Render a hunt result as a plain-text report for history storage."""
    if d.get("error"):
        return f"HUNT: {query}\nError: {d['error']}"
    total = d.get("total", 0)
    lines = [f"HUNT: {query}",
             f"Type: {d.get('hunt_type','?')}  |  Period: last {days} days",
             f"Matches: {total}"]
    if d.get("max_sev"):
        lines.append(f"Max severity: {d['max_sev']}")
    lines.append("")
    if total == 0:
        lines.append("No matches found.")
        return "\n".join(lines)
    if d.get("by_agent"):
        lines.append("AFFECTED AGENTS")
        for b in d["by_agent"]:
            name = (b.get("name",{}).get("buckets",[{}]) or [{}])
            name = name[0].get("key", b["key"]) if name else b["key"]
            lines.append(f"- {name}: {b['doc_count']} events")
        lines.append("")
    if d.get("by_rule"):
        lines.append("MATCHED RULES")
        for b in d["by_rule"]:
            lines.append(f"- {b['key']}  ({b['doc_count']})")
        lines.append("")
    if d.get("samples"):
        lines.append("RECENT MATCHES")
        for s in d["samples"][:10]:
            ts    = (s.get("timestamp","") or "")[:19].replace("T"," ")
            agent = (s.get("agent",{}) or {}).get("name","?")
            rule  = (s.get("rule",{}) or {}).get("description","")
            lvl   = (s.get("rule",{}) or {}).get("level","")
            lines.append(f"- {ts}  {agent}  [{lvl}]  {rule}")
    return "\n".join(lines)


@app.route("/schedule", methods=["POST"])
def set_schedule():
    ST.sched_cfg.update(request.get_json())
    ST.sched_wake.set()
    return jsonify(ST.sched_cfg)


@app.route("/status")
def status():
    return jsonify({
        "running": ST.lock.locked(),
        "model":   OLLAMA_MODEL,
        "schedule": ST.sched_cfg,
    })


# ── Scheduler ─────────────────────────────────────────────────────────────────
def _scheduler():
    while True:
        cfg = ST.sched_cfg
        if not cfg["enabled"]:
            ST.sched_wake.wait(60)
            ST.sched_wake.clear()
            continue
        last  = getattr(ST, "_last_sched", 0)
        wait  = max(0, last + cfg["interval_hours"]*3600 - time.time())
        if wait > 0:
            ST.sched_wake.wait(wait)
            ST.sched_wake.clear()
            continue
        if ST.lock.acquire(blocking=False):
            ST.stop.clear()
            run_id = "sched_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            with ST.hist_lock:
                ST.history[run_id] = {
                    "id": run_id, "label": f"Scheduled — sev={cfg['severity']} hrs={cfg['hours']}",
                    "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "ended": None, "status": "running", "report": "",
                }
            q = queue.Queue()
            t = threading.Thread(target=_run,
                                 args=("", cfg["severity"], cfg["hours"],
                                       cfg.get("agent",""), q, run_id),
                                 daemon=True)
            t.start()
            while True:
                try:
                    chunk = q.get(timeout=600)
                except queue.Empty:
                    break
                if chunk == "__DONE__": break
            ST.lock.release()
            ST._last_sched = time.time()



# ── Context engine ────────────────────────────────────────────────────────────
def _extract_context(reports):
    """
    Extract structured facts from past reports deterministically.
    No model inference — only pattern matching on known report format fields.
    Returns a list of fact dicts safe to pass as context.
    """
    import re
    facts = []
    for r in reports:
        rep = r.get("report", "")
        if not rep or len(rep) < 100:
            continue
        fact = {
            "id":      r["id"],
            "date":    r.get("started", "")[:10],
            "label":   r.get("label", ""),
            "status":  r.get("status", ""),
        }
        # Extract risk level
        m = re.search(r"RISK\s*[:\-–]\s*(CRITICAL|HIGH|MEDIUM|LOW)", rep, re.IGNORECASE)
        if m: fact["risk"] = m.group(1).upper()

        # Extract MITRE techniques (T followed by 4 digits)
        fact["mitre"] = list(set(re.findall(r"T\d{4}(?:\.\d{3})?", rep)))[:6]

        # Extract agent IDs mentioned
        fact["agents"] = list(set(re.findall(r"\bID\s*:\s*(\d{3})\b", rep)))

        # Extract file paths (common patterns)
        fact["files"] = list(set(re.findall(
            r"(?:/etc/[\w./\-]+|/boot/[\w./\-]+|/var/[\w./\-]+|C:\\[\w\\.\-]+)",
            rep)))[:8]

        # Extract assessment line
        m = re.search(r"ASSESSMENT\s*\**\s*\n\s*(.{10,120})", rep, re.IGNORECASE)
        if m: fact["assessment"] = m.group(1).strip()

        facts.append(fact)
    return facts


@app.route("/context", methods=["POST"])
def ask_context():
    """
    Answer a follow-up question using past investigation reports as context.
    Uses Ollama with structured facts — never raw report text to prevent
    the model from inventing connections that aren't there.
    """
    data     = request.get_json() or {}
    question = (data.get("question") or "").strip()
    run_ids  = data.get("run_ids", [])   # specific reports to include, or empty = all

    if not question:
        return jsonify({"error": "no question"}), 400

    import ollama as _ol
    client = _ol.Client(host=os.getenv("OLLAMA_HOST", "http://localhost:11434"))

    with ST.hist_lock:
        if run_ids:
            reports = [ST.history[i] for i in run_ids if i in ST.history]
        else:
            reports = [v for v in ST.history.values() if v.get("status") == "completed"]

    if not reports:
        return jsonify({"answer": "No completed investigations available to answer from."})

    facts = _extract_context(reports)
    if not facts:
        return jsonify({"answer": "Could not extract structured context from the available reports."})

    facts_text = json.dumps(facts, indent=2)

    system = (
        "You are a SOC analyst assistant. You have access to structured facts "
        "extracted from past security investigations.\n\n"
        "STRICT RULES:\n"
        "1. Only use the facts provided. Never infer connections not in the data.\n"
        "2. If events from different investigations are not clearly linked by "
        "shared agent, file, IP, or technique — say they are NOT linked.\n"
        "3. If the question cannot be answered from the provided facts, say so explicitly.\n"
        "4. Be concise. Name specific evidence (dates, files, techniques, agents).\n"
        "5. Never fabricate MITRE technique IDs or file paths not in the facts."
    )

    prompt = (
        f"PAST INVESTIGATION FACTS:\n{facts_text}\n\n"
        f"ANALYST QUESTION: {question}\n\n"
        "Answer based strictly on the facts above."
    )

    try:
        resp = client.chat(
            model=os.getenv("OLLAMA_MODEL", "qwen3"),
            messages=[{"role": "system", "content": system},
                      {"role": "user",   "content": prompt}],
            stream=False,
            options={"temperature": 0}
        )
        answer = resp.message.content.strip()
    except Exception as e:
        answer = f"[Model error: {e}]"

    return jsonify({"answer": answer, "sources": len(facts)})



# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Correlation Agent</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0d1117;color:#e6edf3;
  display:flex;flex-direction:column;height:100vh;overflow:hidden}

/* ── Header ── */
header{background:#161b22;border-bottom:1px solid #30363d;
  padding:10px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}
header h1{font-size:15px;font-weight:600;color:#58a6ff}
.badge{font-size:11px;padding:2px 8px;border-radius:10px;
  background:#1f6feb22;color:#58a6ff;border:1px solid #1f6feb55}
.hdr-tabs{display:flex;gap:2px;margin-left:20px}
.hdr-tab{font-size:12px;padding:4px 14px;border-radius:4px;cursor:pointer;
  color:#8b949e;border:1px solid transparent;background:none}
.hdr-tab:hover{color:#e6edf3;background:#21262d}
.hdr-tab.active{color:#e6edf3;background:#21262d;border-color:#30363d}
.hdr-tab .dot{display:inline-block;width:6px;height:6px;border-radius:50%;
  background:#3fb950;margin-right:5px;vertical-align:middle;
  animation:blink 1.2s infinite;display:none}
.hdr-tab.running .dot{display:inline-block}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* ── Tab panels ── */
.tab{display:none;flex:1;overflow:hidden;flex-direction:column}
.tab.active{display:flex}

/* ── RUN TAB ── */
.run-tab{flex:1;display:flex;flex-direction:column;overflow:hidden}
.controls{padding:14px 20px;border-bottom:1px solid #30363d;flex-shrink:0}
.nl-wrap{position:relative;margin-bottom:10px}
#nl-input{width:100%;background:#0d1117;border:1px solid #388bfd55;
  border-radius:6px;color:#e6edf3;font-size:13px;
  padding:10px 80px 10px 12px;font-family:monospace}
#nl-input:focus{outline:none;border-color:#58a6ff}
#nl-input::placeholder{color:#484f58}
.nl-btn{position:absolute;right:5px;top:50%;transform:translateY(-50%);
  background:#1f6feb;border:none;border-radius:4px;color:#fff;
  cursor:pointer;font-size:12px;padding:5px 12px}
.nl-btn:hover{opacity:.85}
#nl-preview{background:#0d1117;border:1px solid #30363d;border-radius:5px;
  padding:8px 12px;font-size:12px;color:#8b949e;display:none;
  margin-bottom:8px}
#nl-preview strong{color:#3fb950}
.params{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.field{flex:1;min-width:80px}
label{font-size:11px;color:#8b949e;display:block;margin-bottom:3px}
input[type=number],input[type=text],select{background:#0d1117;
  border:1px solid #30363d;border-radius:5px;color:#e6edf3;
  font-size:12px;padding:6px 8px;width:100%;font-family:monospace}
input:focus,select:focus{outline:none;border-color:#58a6ff}
button{border:none;border-radius:5px;cursor:pointer;font-size:12px;
  font-weight:500;padding:7px 16px;transition:opacity .15s}
button:disabled{opacity:.35;cursor:not-allowed}
.btn-run{background:#1f6feb;color:#fff}
.btn-run:hover:not(:disabled){opacity:.85}
.btn-stop{background:#da3633;color:#fff}
.btn-stop:hover:not(:disabled){opacity:.85}
.hint{font-size:10px;color:#484f58;margin-top:6px}

.sched-bar{padding:6px 20px;border-bottom:1px solid #30363d;
  display:flex;align-items:center;gap:8px;flex-shrink:0}
.toggle{position:relative;width:32px;height:18px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#484f58;border-radius:9px;
  cursor:pointer;transition:.2s}
.slider:before{content:"";position:absolute;height:12px;width:12px;
  left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
input:checked+.slider{background:#1f6feb}
input:checked+.slider:before{transform:translateX(14px)}
.si{font-size:11px;color:#8b949e}

/* Live output */
.live-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden;
  padding:0}
.live-header{display:flex;align-items:center;gap:8px;padding:8px 20px;
  border-bottom:1px solid #21262d;flex-shrink:0}
.live-dot{width:7px;height:7px;border-radius:50%;background:#484f58;flex-shrink:0}
.live-dot.running{background:#3fb950;animation:blink 1.2s infinite}
.live-dot.error{background:#f85149}
.live-title{font-size:11px;font-weight:600;color:#8b949e;
  text-transform:uppercase;letter-spacing:.05em}
.elapsed{font-size:11px;color:#484f58}
#live-out{flex:1;padding:14px 20px;overflow-y:auto;font-size:12.5px;
  line-height:1.7;word-break:break-word;white-space:pre-wrap}
#live-out.md-body{white-space:normal}
.status-bar{padding:6px 20px;font-size:11px;color:#8b949e;
  border-top:1px solid #21262d;flex-shrink:0;display:flex;
  align-items:center;gap:8px}

/* ── REPORTS TAB ── */
.reports-tab{flex:1;display:flex;overflow:hidden}
.reports-sidebar{width:260px;min-width:260px;border-right:1px solid #30363d;
  display:flex;flex-direction:column}
.sb-head{padding:10px 14px;font-size:10px;font-weight:700;color:#8b949e;
  text-transform:uppercase;letter-spacing:.07em;
  border-bottom:1px solid #30363d}
.hist-list{flex:1;overflow-y:auto;padding:4px}
.hi{padding:8px 10px;border-radius:5px;cursor:pointer;margin-bottom:2px;
  border:1px solid transparent}
.hi:hover{background:#21262d}
.hi.active{background:#1f3a5f;border-color:#1f6feb}
.hl{font-size:12px;color:#e6edf3;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.hm{font-size:10px;color:#8b949e;margin-top:2px;display:flex;
  gap:5px;align-items:center}
.ds{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.ds.running{background:#3fb950;animation:blink 1.2s infinite}
.ds.completed{background:#3fb950}
.ds.error{background:#f85149}

.report-main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.report-header{padding:10px 18px;border-bottom:1px solid #30363d;
  font-size:12px;font-weight:600;color:#8b949e;flex-shrink:0}
#report-out{flex:1;padding:16px 20px;overflow-y:auto;font-size:13px;
  line-height:1.75;word-break:break-word}

/* Context Q&A */
.ctx-panel{border-top:1px solid #30363d;padding:10px 18px;flex-shrink:0}
.ctx-label{font-size:10px;font-weight:700;color:#8b949e;
  text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
.ctx-row{display:flex;gap:6px}
#ctx-input{flex:1;background:#0d1117;border:1px solid #30363d;
  border-radius:5px;color:#e6edf3;font-size:12px;
  padding:7px 10px;font-family:monospace}
#ctx-input:focus{outline:none;border-color:#58a6ff}
#ctx-input::placeholder{color:#484f58}
.btn-ask{background:#534ab7;color:#fff;white-space:nowrap}
.btn-ask:hover:not(:disabled){opacity:.85}
#ctx-answer{margin-top:8px;font-size:12px;color:#c9d1d9;
  white-space:pre-wrap;display:none;padding:8px 10px;
  background:#161b22;border-radius:5px;border:1px solid #30363d;
  line-height:1.6}
#ctx-src{font-size:10px;color:#484f58;margin-top:4px}

.confirm-yes{padding:5px 16px;background:#238636;border:none;border-radius:5px;
  color:#fff;font-size:12px;cursor:pointer;margin-right:8px}
.confirm-yes:hover{background:#2ea043}
.confirm-no{padding:5px 16px;background:#21262d;border:1px solid #30363d;
  border-radius:5px;color:#8b949e;font-size:12px;cursor:pointer}
.confirm-no:hover{color:#e6edf3}

/* Rendered markdown styles */
.md-body h1,.md-body h2,.md-body h3{color:#58a6ff;margin:10px 0 4px;font-size:13px;font-weight:700}
.md-body p{margin:0 0 6px}
.md-body ul,.md-body ol{padding-left:18px;margin:0 0 6px}
.md-body li{margin:2px 0;line-height:1.6;white-space:normal}
.md-body strong{color:#e6edf3;font-weight:700}
.md-body code{background:#21262d;padding:1px 5px;border-radius:3px;font-size:11px}
.md-body pre{background:#21262d;padding:10px;border-radius:5px;overflow-x:auto;margin:6px 0}
.md-body table{border-collapse:collapse;width:100%;margin:6px 0;font-size:11px}
.md-body th,.md-body td{border:1px solid #30363d;padding:4px 8px;text-align:left}
.md-body th{background:#21262d;color:#58a6ff}
.md-body hr{border:none;border-top:1px solid #30363d;margin:8px 0}
.hbtn{margin-left:5px;font-size:10px;padding:2px 7px;background:#21262d;border:1px solid #30363d;border-radius:3px;cursor:pointer}
.md-body blockquote{border-left:3px solid #30363d;padding-left:10px;color:#8b949e;margin:4px 0}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"></script>
<script>
if (typeof marked !== 'undefined') {
  marked.setOptions({
    breaks: true,      // single newlines become <br>
    gfm: true,         // github flavoured markdown
    mangle: false,
    headerIds: false
  });
}
</script>
</head>
<body>

<header>
  <span class="badge" id="model-badge">{{ model }}</span>
  <span class="badge" id="status-badge">idle</span>
  <div class="hdr-tabs">
    <div class="hdr-tab active" id="tab-run-btn" onclick="switchTab('run')">
      <span class="dot"></span>Run
    </div>
    <div class="hdr-tab" id="tab-reports-btn" onclick="switchTab('reports')">
      Reports
    </div>

  </div>
</header>

<!-- ── RUN TAB ── -->
<div class="tab active" id="tab-run">
  <div class="run-tab">

    <div class="controls">
      <div class="nl-wrap">
        <input id="nl-input" type="text" autocomplete="off" spellcheck="false"
          placeholder="check agent 001 last 2h  |  find 185.220.101.45  |  hunt pass the hash  |  show ports on agent 001"
          onkeydown="if(event.key==='Enter')parseAndConfirm()">
      </div>
      <div id="nl-preview"></div>
      <div class="params">
        <div class="field">
          <label>Min severity</label>
                    <select id="severity">
            <option value="2">2</option>
            <option value="3">3</option>
            <option value="4">4</option>
            <option value="5">5</option>
            <option value="6">6</option>
            <option value="7" selected>7</option>
            <option value="8">8</option>
            <option value="9">9</option>
            <option value="10">10</option>
            <option value="11">11</option>
            <option value="12">12</option>
            <option value="13">13</option>
            <option value="14">14</option>
            <option value="15">15</option>
          </select>
        </div>
        <div class="field">
          <label>Look-back hours</label>
          <input type="number" id="hours" value="24" min="1" max="168">
        </div>
        <div class="field">
          <label>Agent ID (blank = all)</label>
          <input type="text" id="agent" placeholder="e.g. 000">
        </div>
        <div style="display:flex;gap:6px;align-items:flex-end">
          <button class="btn-run" id="run-btn" onclick="parseAndConfirm()">Run now</button>
          <button class="btn-stop" id="stop-btn" onclick="stopRun()" disabled>Stop</button>
        </div>
      </div>
      <p class="hint">Type what you want — e.g. "check agent 001 last 2h" or "find pass the hash attempts this week" — then press Enter or click Parse.</p>
    </div>

    <div class="sched-bar">
      <label class="toggle">
        <input type="checkbox" id="sched-on" onchange="updateSched()">
        <span class="slider"></span>
      </label>
      <span class="si">Auto-run every</span>
      <input type="number" id="sched-hours" value="8" min="1" max="72"
        style="width:52px" onchange="updateSched()">
      <span class="si">hours — severity</span>
      <select id="sched-sev" style="width:160px" onchange="updateSched()">
        <option value="3">3</option>
        <option value="5">5</option>
        <option value="7" selected>7</option>
        <option value="10">10</option>
        <option value="12">12</option>
        <option value="14">14</option>
        <option value="15">15 - exploit successful</option>
      </select>
      <span class="si" id="sched-status" style="margin-left:4px">Off</span>
    </div>

    <div class="live-wrap">
      <div class="live-header">
        <div class="live-dot" id="dot"></div>
        <span class="live-title" id="live-title">Output</span>
        <span class="elapsed" id="elapsed"></span>
        <button id="copy-live-btn" onclick="copyLive()"
          style="margin-left:auto;font-size:11px;padding:3px 10px;
          background:#21262d;color:#8b949e;border:1px solid #30363d;
          border-radius:4px;cursor:pointer">Copy</button>
      </div>
      <div id="live-out" class="md-body">Ready. Configure parameters above and click Run now.</div>
      <div class="status-bar">
        <span id="status-text">idle</span>
        <span style="margin-left:auto" id="last-run"></span>
      </div>
    </div>

  </div>
</div>

<!-- ── REPORTS TAB ── -->
<div class="tab" id="tab-reports">
  <div class="reports-tab">

    <!-- Sidebar -->
    <div class="reports-sidebar">
      <div class="sb-head">Investigation history</div>
      <div class="hist-list" id="hist-list">
        <div style="padding:10px;font-size:11px;color:#484f58">
          No investigations yet.
        </div>
      </div>
    </div>

    <!-- Report viewer -->
    <div class="report-main">
      <div class="report-header" id="report-header"
           style="display:flex;align-items:center;justify-content:space-between">
        <span id="report-header-text">Select an investigation from the sidebar</span>
        <button id="copy-btn" onclick="copyReport()"
          style="font-size:11px;padding:3px 10px;background:#21262d;
          color:#8b949e;border:1px solid #30363d;border-radius:4px;
          cursor:pointer;display:none">Copy</button>
      </div>
      <div id="report-out" class="md-body">
        Click any investigation in the sidebar to read its report.
      </div>

      <!-- Context Q&A -->
      <div class="ctx-panel">
        <div class="ctx-label">Ask about past investigations</div>
        <div class="ctx-row">
          <input id="ctx-input" type="text" autocomplete="off"
            placeholder="e.g. Has agent 000 had similar file changes before? Are there recurring MITRE techniques?">
          <button class="btn-ask" id="ask-btn" onclick="askContext()">Ask</button>
        </div>
        <div id="ctx-answer"></div>
        <div id="ctx-src"></div>
      </div>
    </div>

  </div>
</div>

<script>
// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.hdr-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('tab-' + name + '-btn').classList.add('active');
  if (name === 'reports') loadHistory();
}

// ── NL parser ─────────────────────────────────────────────────────────────────
function parseAndConfirm() {
  const text = document.getElementById('nl-input').value.trim();
  // If no NL text, fall back to manual params from the form fields
  if (!text) { startRun(); return; }

  fetch('/parse', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text})})
  .then(r => r.json())
  .then(d => {
    _pendingAction = d;   // store for confirmation
    const p = document.getElementById('nl-preview');
    p.style.display = 'block';
    const isHunt   = d.intent === 'hunt_ioc' || d.intent === 'hunt_ttp';
    const isInv    = d.intent === 'inventory';
    const isThreat = d.intent === 'threat_category';
    const isTriage = d.intent === 'triage';
    const label  = isTriage ? 'Triage' : isThreat ? 'Threat Hunt'
                 : isInv ? 'Inventory' : isHunt ? 'Hunt' : 'Investigate';
    const color  = isTriage ? '#bf4080' : isThreat ? '#db6d28'
                 : isInv ? '#a371f7' : isHunt ? '#1f6feb' : '#238636';
    p.innerHTML =
        '<div style="margin-bottom:8px">'
      + '<strong style="color:' + color + '">' + label + '</strong>'
      + '<span style="color:#8b949e"> — </span>'
      + '<strong>' + esc(d.summary) + '</strong></div>'
      + '<button class="confirm-yes" onclick="confirmRun()">Yes, run this</button>'
      + '<button class="confirm-no" onclick="cancelConfirm()">Cancel</button>';
  })
  .catch(e => {
    document.getElementById('nl-preview').style.display = 'block';
    document.getElementById('nl-preview').innerHTML =
      '<span style="color:#f85149">Parse failed: ' + e + '</span>';
  });
}

function cancelConfirm() {
  _pendingAction = null;
  document.getElementById('nl-preview').style.display = 'none';
}

function confirmRun() {
  const d = _pendingAction;
  document.getElementById('nl-preview').style.display = 'none';
  if (!d) { startRun(); return; }
  if (d.intent === 'triage') {
    runTriage(d.hours || 24, d.agent || '');
  } else if (d.intent === 'threat_category') {
    runThreatHunt(d.threat_cat, d.hours || 24, d.agent || '');
  } else if (d.intent === 'inventory') {
    runInventory(d.inv_kind, d.agent || '', d.only_suspicious || false);
  } else if (d.intent === 'hunt_ioc' || d.intent === 'hunt_ttp') {
    runHuntFromNL(d.query || '', d.days || 7, d.agent || '', d.hunt_type || 'auto');
  } else {
    document.getElementById('severity').value = d.severity;
    document.getElementById('hours').value    = d.hours;
    document.getElementById('agent').value    = d.agent;
    startRun();
  }
}


function runTriage(hours, agent) {
  _stoppable = false;
  document.getElementById('nl-preview').style.display = 'none';
  const out = document.getElementById('live-out');
  out.classList.remove('md-body');
  _liveBuffer = '';
  document.getElementById('live-title').textContent = 'Alert Triage';
  document.getElementById('dot').className = 'live-dot running';
  setRunning(true);
  out.innerHTML = '<div style="color:#8b949e;font-size:12px;padding:8px 0">'
    + 'Triaging alerts across last ' + hours + 'h (scoring by severity, '
    + 'MITRE tags, density, and rarity)...</div>';

  fetch('/triage', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({hours, agent: agent||null})
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('dot').className = 'live-dot';
    setRunning(false);
    if (d.error) {
      out.innerHTML = '<div style="color:#f85149">Error: ' + esc(d.error) + '</div>';
      return;
    }
    _liveBuffer = _formatTriage(d);
    out.innerHTML = _liveBuffer;
    _loadHistoryData();
  })
  .catch(e => {
    setRunning(false);
    document.getElementById('dot').className = 'live-dot error';
    out.innerHTML = '<div style="color:#f85149">Request failed: ' + e + '</div>';
  });
}

function _formatTriage(d) {
  let html = '<div style="font-size:15px;font-weight:600;color:#bf4080;margin-bottom:4px">'
           + 'Alert Triage</div>';

  if (d.total === 0) {
    html += '<div style="color:#3fb950;font-size:13px;padding:10px 0">'
          + '✓ No alerts in the last ' + d.hours + 'h. Nothing to triage.</div>';
    return html;
  }

  html += '<div style="color:#8b949e;font-size:12px;margin-bottom:14px">'
        + d.total + ' alerts grouped into ' + d.situations + ' situations '
        + '<span style="color:#484f58">· last ' + d.hours + 'h</span></div>';

  const buckets = [
    ['urgent', 'URGENT — investigate now', '#f85149', '🔴'],
    ['review', 'REVIEW — needs a look',     '#f0883e', '🟠'],
    ['routine','ROUTINE / LIKELY NOISE',    '#3fb950', '🟢'],
  ];

  buckets.forEach(([key, title, color, dot]) => {
    const items = d[key] || [];
    if (!items.length) return;
    html += '<div style="font-size:11px;font-weight:700;color:' + color + ';'
          + 'text-transform:uppercase;letter-spacing:.5px;margin:16px 0 8px">'
          + dot + ' ' + title + ' (' + items.length + ')</div>';
    items.forEach(s => {
      const agents  = s.agents.slice(0,3).join(', ');
      const tactics = s.tactics.length ? s.tactics.slice(0,3).join(', ') : 'no MITRE tactic';
      const lc = (s.max_level>=13)?'#f85149':(s.max_level>=10)?'#f0883e':'#8b949e';
      const sample = s.sample || {};
      const sdesc  = sample['rule.description'] || (s.top_rules[0] || '');
      const focusList = (s.focus || []).map(f =>
        '<li style="margin:1px 0">' + esc(f) + '</li>').join('');
      html += '<div style="background:#161b22;border:1px solid #21262d;'
            + 'border-left:3px solid ' + color + ';border-radius:4px;'
            + 'padding:10px 12px;margin-bottom:8px">'
            // Header: group name + score
            + '<div style="display:flex;justify-content:space-between;align-items:center">'
            + '<span style="color:#e6edf3;font-size:13px;font-weight:600">'
            + esc(s.group) + '</span>'
            + '<span style="font-size:10px;color:#484f58">score ' + s.score + '</span>'
            + '</div>'
            // Metadata line
            + '<div style="font-size:11px;color:#8b949e;margin-top:3px">'
            + '<span style="color:' + lc + '">[sev ' + s.max_level + ']</span>'
            + ' · ' + s.count + ' events · ' + esc(agents)
            + ' · <span style="color:#a371f7">' + esc(tactics) + '</span>'
            + '</div>'
            // Sample rule
            + (sdesc ? '<div style="font-size:11px;color:#6e7681;margin-top:3px;'
               + 'font-family:monospace">' + esc(sdesc) + '</div>' : '')
            // WHY
            + (s.reason ? '<div style="font-size:11px;margin-top:8px">'
               + '<span style="color:#8b949e;font-weight:600">Why: </span>'
               + '<span style="color:#c9d1d9">' + esc(s.reason) + '</span></div>' : '')
            // WHAT TO LOOK AT
            + (focusList ? '<div style="font-size:11px;margin-top:5px">'
               + '<span style="color:#8b949e;font-weight:600">Look at:</span>'
               + '<ul style="margin:2px 0 0;padding-left:18px;color:#c9d1d9">'
               + focusList + '</ul></div>' : '')
            // ACTION
            + (s.action ? '<div style="font-size:11px;margin-top:6px;'
               + 'color:' + color + '">▸ ' + esc(s.action) + '</div>' : '')
            + '</div>';
    });
  });

  html += '<div style="font-size:10px;color:#484f58;margin-top:14px;'
        + 'border-top:1px solid #21262d;padding-top:8px">'
        + 'Scored by: severity + MITRE-tag presence + event density − rarity penalty. '
        + 'No hardcoded scenarios. Investigate any situation for full behavior analysis.</div>';
  return html;
}

function runThreatHunt(category, hours, agent) {
  _stoppable = false;
  document.getElementById('nl-preview').style.display = 'none';
  const out = document.getElementById('live-out');
  out.classList.remove('md-body');
  _liveBuffer = '';
  document.getElementById('live-title').textContent = 'Threat Hunt';
  document.getElementById('dot').className = 'live-dot running';
  setRunning(true);
  out.innerHTML = '<div style="color:#8b949e;font-size:12px;padding:8px 0">'
    + 'Hunting for ' + esc(category) + ' indicators across last ' + hours + 'h...</div>';

  fetch('/threat', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({category, hours, agent: agent||null})
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('dot').className = 'live-dot';
    setRunning(false);
    if (d.error) {
      out.innerHTML = '<div style="color:#f85149">Error: ' + esc(d.error) + '</div>';
      return;
    }
    _liveBuffer = _formatThreat(d);
    out.innerHTML = _liveBuffer;
    _loadHistoryData();
  })
  .catch(e => {
    setRunning(false);
    document.getElementById('dot').className = 'live-dot error';
    out.innerHTML = '<div style="color:#f85149">Request failed: ' + e + '</div>';
  });
}

function _formatThreat(d) {
  const total = d.total || 0;
  const sevColor = (d.max_sev >= 13) ? '#f85149' : (d.max_sev >= 10) ? '#f0883e' : '#3fb950';
  let html = '';

  // Title
  html += '<div style="font-size:15px;font-weight:600;color:#db6d28;margin-bottom:4px">'
        + esc(d.label) + '</div>';

  if (total === 0) {
    html += '<div style="color:#3fb950;font-size:13px;padding:10px 0">'
          + '✓ No ' + esc(d.label.toLowerCase()) + ' activity detected in the last '
          + d.hours + ' hours.</div>';
    return html;
  }

  // Summary strip
  html += '<div style="display:flex;gap:20px;flex-wrap:wrap;padding:10px 0 14px;'
        + 'border-bottom:1px solid #21262d;margin-bottom:14px">';
  const stats = [
    ['Events', String(total), sevColor],
    ['Max severity', d.max_sev ? String(d.max_sev) : '—', sevColor],
    ['Agents', String((d.by_agent||[]).length), '#e6edf3'],
    ['Period', 'last ' + d.hours + 'h', '#8b949e'],
  ];
  stats.forEach(([l,v,col]) => {
    html += '<div><div style="font-size:10px;color:#484f58;text-transform:uppercase">'
          + l + '</div><div style="font-size:14px;font-weight:600;color:' + col + '">'
          + esc(v) + '</div></div>';
  });
  html += '</div>';

  if (d.tactics && d.tactics.length) {
    html += '<div style="font-size:11px;color:#8b949e;margin-bottom:12px">'
          + 'MITRE tactics: <span style="color:#db6d28">' + d.tactics.join(', ')
          + '</span></div>';
  }

  // Affected agents
  if (d.by_agent && d.by_agent.length) {
    html += _huntSection('Affected agents');
    d.by_agent.forEach(b => {
      const nm = (b.name && b.name.buckets && b.name.buckets[0]) ? b.name.buckets[0].key : b.key;
      html += '<div style="display:flex;gap:10px;padding:4px 0;border-bottom:1px solid #161b22;font-size:12px">'
            + '<span style="color:#58a6ff;width:130px">' + esc(nm) + '</span>'
            + '<span style="color:#e6edf3;font-weight:600">' + b.doc_count + ' events</span></div>';
    });
  }

  // Top rules
  if (d.by_rule && d.by_rule.length) {
    html += _huntSection('Top matched rules');
    d.by_rule.forEach(b => {
      html += '<div style="display:flex;justify-content:space-between;padding:3px 0;'
            + 'border-bottom:1px solid #161b22;font-size:12px">'
            + '<span style="color:#8b949e">' + esc(b.key) + '</span>'
            + '<span style="color:#e6edf3;font-weight:600">' + b.doc_count + '</span></div>';
    });
  }

  // Highest-severity sample events
  if (d.samples && d.samples.length) {
    html += _huntSection('Highest-severity events');
    d.samples.forEach(s => {
      const ts = (s.timestamp||'').slice(0,19).replace('T',' ');
      const agent = (s.agent||{}).name || (s.agent||{}).id || '?';
      const rule = (s.rule||{}).description || '';
      const lvl = (s.rule||{}).level || '';
      const lc = (lvl>=13)?'#f85149':(lvl>=10)?'#f0883e':'#8b949e';
      html += '<div style="background:#161b22;border:1px solid #21262d;border-radius:4px;'
            + 'padding:8px 10px;margin-bottom:6px;font-size:11px;font-family:monospace">'
            + '<div style="color:#8b949e;margin-bottom:3px">' + esc(ts)
            + '&nbsp;&nbsp;<span style="color:#58a6ff">' + esc(agent) + '</span>'
            + '&nbsp;&nbsp;<span style="color:' + lc + '">[' + lvl + ']</span></div>'
            + '<div style="color:#e6edf3">' + esc(rule) + '</div></div>';
    });
  }
  return html;
}

function runInventory(kind, agent, onlySuspicious) {
  _stoppable = false;
  document.getElementById('nl-preview').style.display = 'none';
  if (!agent) {
    const out = document.getElementById('live-out');
    out.classList.remove('md-body');
    out.innerHTML = '<div style="color:#f85149;padding:8px 0">'
      + 'Inventory queries need an agent ID. Try "show ports on agent 001".</div>';
    return;
  }
  const out = document.getElementById('live-out');
  out.classList.remove('md-body');
  _liveBuffer = '';
  document.getElementById('live-title').textContent =
    kind.charAt(0).toUpperCase() + kind.slice(1) + ' — agent ' + agent;
  document.getElementById('dot').className = 'live-dot running';
  setRunning(true);
  out.innerHTML = '<div style="color:#8b949e;font-size:12px;padding:8px 0">'
    + 'Querying ' + kind + ' on agent ' + esc(agent) + '...</div>';

  fetch('/inventory', {
    method:  'POST',
    headers: {'Content-Type':'application/json'},
    body:    JSON.stringify({kind, agent, only_suspicious: onlySuspicious || false})
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('dot').className = 'live-dot';
    setRunning(false);
    if (d.error) {
      out.innerHTML = '<div style="color:#f85149">Error: ' + esc(d.error) + '</div>';
      return;
    }
    _liveBuffer = _formatInventory(d);
    out.innerHTML = _liveBuffer;
  })
  .catch(e => {
    setRunning(false);
    document.getElementById('dot').className = 'live-dot error';
    out.innerHTML = '<div style="color:#f85149">Request failed: ' + e + '</div>';
  });
}

function _formatInventory(d) {
  let html = '';
  // Summary strip
  html += '<div style="display:flex;gap:20px;padding:10px 0 14px;'
        + 'border-bottom:1px solid #21262d;margin-bottom:14px">';
  html += '<div><div style="font-size:10px;color:#484f58;text-transform:uppercase">Type</div>'
        + '<div style="font-size:14px;font-weight:600;color:#a371f7">' + esc(d.kind) + '</div></div>';
  html += '<div><div style="font-size:10px;color:#484f58;text-transform:uppercase">Agent</div>'
        + '<div style="font-size:14px;font-weight:600;color:#58a6ff">' + esc(d.agent) + '</div></div>';
  html += '<div><div style="font-size:10px;color:#484f58;text-transform:uppercase">Total</div>'
        + '<div style="font-size:14px;font-weight:600;color:#e6edf3">' + d.count + '</div></div>';
  html += '</div>';

  // Flagged items first
  if (d.flags && d.flags.length) {
    html += '<div style="font-size:10px;font-weight:600;color:#f85149;text-transform:uppercase;'
          + 'letter-spacing:.5px;margin-bottom:6px">⚠ Flagged (' + d.flags.length + ')</div>';
    d.flags.forEach(f => {
      html += '<div style="background:#2d1416;border:1px solid #f8514944;border-radius:4px;'
            + 'padding:6px 10px;margin-bottom:4px;font-size:12px;color:#ffa198;'
            + 'font-family:monospace">' + esc(f) + '</div>';
    });
    html += '<div style="height:12px"></div>';
  }

  // Build table by kind
  const rows = d.rows || [];
  if (!rows.length) {
    if (d.only_suspicious) {
      html += '<div style="color:#3fb950;font-size:13px;padding:10px 0">'
            + '✓ No suspicious ' + esc(d.kind) + ' found on agent ' + esc(d.agent)
            + '. Nothing matched the known-bad indicators.</div>';
    } else {
      html += '<div style="color:#484f58;font-size:12px">No data returned. '
            + 'Agent may be offline or have no ' + esc(d.kind) + ' inventory.</div>';
    }
    return html;
  }
  // Banner when showing suspicious-only results
  if (d.only_suspicious) {
    html = '<div style="color:#f0883e;font-size:12px;padding:6px 0 10px">'
         + '⚠ Showing only suspicious ' + esc(d.kind) + ' ('
         + rows.length + ' flagged)</div>' + html;
  }

  let cols = [];
  if (d.kind === 'ports')     cols = [['port','Port',60],['protocol','Proto',60],['state','State',110],['process','Process',200]];
  if (d.kind === 'processes') cols = [['name','Process',160],['pid','PID',60],['ppid','PPID',60],['cmd','Command',300]];
  if (d.kind === 'packages')  cols = [['name','Package',220],['version','Version',120],['vendor','Vendor',220]];
  if (d.kind === 'files')     cols = [['file','File',360],['mtime','Modified',150],['hash','Hash',140]];

  html += '<table style="width:100%;border-collapse:collapse;font-size:11px;font-family:monospace">';
  html += '<tr style="border-bottom:1px solid #30363d">';
  cols.forEach(([k,label,w]) => {
    html += '<th style="text-align:left;padding:5px 8px;color:#58a6ff;width:' + w + 'px">' + label + '</th>';
  });
  html += '</tr>';
  rows.forEach(r => {
    const rowBg = r._sus ? 'background:#2d1416;' : '';
    const txtCol = r._sus ? '#ffa198' : '#c9d1d9';
    html += '<tr style="border-bottom:1px solid #161b22;' + rowBg + '">';
    cols.forEach(([k]) => {
      html += '<td style="padding:4px 8px;color:' + txtCol + ';word-break:break-all">'
            + esc(String(r[k] != null ? r[k] : '')) + '</td>';
    });
    html += '</tr>';
  });
  html += '</table>';
  if (rows.length >= 100) {
    html += '<div style="color:#484f58;font-size:11px;margin-top:8px">'
          + 'Showing first 100 of ' + d.count + ' — refine with a hunt query for specifics.</div>';
  }
  return html;
}

function runHuntFromNL(query, days, agent, huntType) {
  _stoppable = false;
  document.getElementById('nl-preview').style.display = 'none';
  const out = document.getElementById('live-out');
  out.classList.remove('md-body');
  out.innerHTML = '';
  _liveBuffer   = '';
  document.getElementById('live-title').textContent = 'Hunt — ' + query;
  document.getElementById('dot').className = 'live-dot running';
  setRunning(true);
  _t0    = Date.now();
  _timer = setInterval(() => {
    const s = Math.floor((Date.now()-_t0)/1000);
    document.getElementById('elapsed').textContent = s + 's';
  }, 1000);

  out.innerHTML = '<div style="color:#8b949e;font-size:12px;padding:8px 0">'
    + 'Hunting for <strong style="color:#e6edf3">' + esc(query) + '</strong>'
    + ' across last ' + days + ' days...</div>';

  fetch('/hunt', {
    method:  'POST',
    headers: {'Content-Type':'application/json'},
    body:    JSON.stringify({query, days, agent: agent||null, type: huntType})
  })
  .then(r => r.json())
  .then(d => {
    clearInterval(_timer);
    document.getElementById('elapsed').textContent = '';
    document.getElementById('dot').className = 'live-dot';
    setRunning(false);
    if (d.error) {
      out.innerHTML = '<div style="color:#f85149">Error: ' + esc(d.error) + '</div>';
      return;
    }
    _liveBuffer = _formatHuntResults(d);
    out.innerHTML = _liveBuffer;
    _loadHistoryData();
  })
  .catch(e => {
    clearInterval(_timer);
    setRunning(false);
    document.getElementById('dot').className = 'live-dot error';
    out.innerHTML = '<div style="color:#f85149">Request failed: ' + e + '</div>';
  });
}

function _formatHuntResults(d) {
  const total = d.total || 0;
  if (total === 0) {
    return '<div style="color:#484f58;font-size:12px;padding:12px 0">'
      + 'No matches found for <strong style="color:#8b949e">'
      + esc(d.value || d.ttp_name || '') + '</strong> in the last '
      + d.days + ' days.<br>'
      + 'Either the indicator is not present or events have been rotated out of the index.'
      + '</div>';
  }

  const sevColor = (d.max_sev >= 13) ? '#f85149' : (d.max_sev >= 10) ? '#f0883e' : '#3fb950';
  let html = '';

  // ── Summary strip ─────────────────────────────────────────────────────────
  html += '<div style="display:flex;gap:20px;flex-wrap:wrap;padding:10px 0 14px;'
        + 'border-bottom:1px solid #21262d;margin-bottom:14px">';
  const stats = [
    ['Matches',      String(total),               total > 0 ? sevColor : '#8b949e'],
    ['Type',         d.hunt_type || d.intent,      '#8b949e'],
    ['Indicator',    d.value || d.ttp_name || '',  '#e6edf3'],
    ['Max severity', d.max_sev ? String(d.max_sev) : '—', sevColor],
    ['Period',       'last ' + d.days + ' days',  '#8b949e'],
  ];
  stats.forEach(([label, val, col]) => {
    if (!val || val === 'undefined') return;
    html += '<div><div style="font-size:10px;color:#484f58;text-transform:uppercase'
          + ';letter-spacing:.5px">' + label + '</div>'
          + '<div style="font-size:14px;font-weight:600;color:' + col + '">'
          + esc(val) + '</div></div>';
  });
  html += '</div>';

  // ── Affected agents ───────────────────────────────────────────────────────
  if (d.by_agent && d.by_agent.length) {
    html += _huntSection('Affected agents (' + d.by_agent.length + ')');
    d.by_agent.forEach(b => {
      const name  = (b.name && b.name.buckets && b.name.buckets[0])
                    ? b.name.buckets[0].key : b.key;
      const first = b.first ? (b.first.value_as_string || '').slice(0,10) : '';
      const last  = b.last  ? (b.last.value_as_string  || '').slice(0,10) : '';
      const range = first ? (first + (last && last !== first ? ' → ' + last : '')) : '';
      html += '<div style="display:flex;align-items:center;gap:10px;padding:5px 0;'
            + 'border-bottom:1px solid #161b22;font-size:12px">'
            + '<span style="color:#58a6ff;width:120px;flex-shrink:0">' + esc(name) + '</span>'
            + '<span style="color:#e6edf3;font-weight:600;width:35px">' + b.doc_count + '</span>'
            + '<span style="color:#484f58">' + esc(range) + '</span>'
            + '</div>';
    });
  }

  // ── Matched rules (TTP hunts) ─────────────────────────────────────────────
  if (d.by_rule && d.by_rule.length) {
    html += _huntSection('Matched rules');
    d.by_rule.forEach(b => {
      html += '<div style="display:flex;justify-content:space-between;padding:3px 0;'
            + 'border-bottom:1px solid #161b22;font-size:12px">'
            + '<span style="color:#8b949e">' + esc(b.key) + '</span>'
            + '<span style="color:#e6edf3;font-weight:600">' + b.doc_count + '</span>'
            + '</div>';
    });
  }

  // ── MITRE tactics ─────────────────────────────────────────────────────────
  if (d.by_tactic && d.by_tactic.length) {
    html += _huntSection('MITRE tactics observed');
    d.by_tactic.forEach(b => {
      html += '<div style="display:flex;justify-content:space-between;padding:3px 0;'
            + 'border-bottom:1px solid #161b22;font-size:12px">'
            + '<span style="color:#8b949e">' + esc(b.key) + '</span>'
            + '<span style="color:#e6edf3;font-weight:600">' + b.doc_count + '</span>'
            + '</div>';
    });
  }

  // ── Sample events ─────────────────────────────────────────────────────────
  if (d.samples && d.samples.length) {
    html += _huntSection('Most recent matches');
    d.samples.forEach(src => {
      const ts    = (src.timestamp || '').slice(0,19).replace('T',' ');
      const agent = (src.agent || {}).name || (src.agent || {}).id || '?';
      const rule  = (src.rule  || {}).description || '';
      const level = (src.rule  || {}).level || '';
      const log_  = (src.full_log || '').slice(0, 200);
      html += '<div style="background:#161b22;border:1px solid #21262d;border-radius:4px;'
            + 'padding:8px 10px;margin-bottom:6px;font-size:11px;font-family:monospace">'
            + '<div style="color:#8b949e;margin-bottom:3px">' + esc(ts)
            + '&nbsp;&nbsp;<span style="color:#58a6ff">' + esc(agent) + '</span>'
            + '&nbsp;&nbsp;[' + level + ']</div>'
            + '<div style="color:#e6edf3">' + esc(rule) + '</div>'
            + (log_ ? '<div style="color:#484f58;margin-top:3px;word-break:break-all">'
               + esc(log_) + '</div>' : '')
            + '</div>';
    });
  }
  return html;
}

function _huntSection(title) {
  return '<div style="font-size:10px;font-weight:600;color:#8b949e;text-transform:uppercase;'
       + 'letter-spacing:.5px;margin:14px 0 6px;border-bottom:1px solid #21262d;padding-bottom:4px">'
       + title + '</div>';
}
document.getElementById('nl-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') parseAndConfirm();
});

// ── Run control ───────────────────────────────────────────────────────────────
let _es=null, _running=false, _t0=0, _timer=null, _liveBuffer='', _pendingAction=null, _stoppable=false;

function setRunning(on) {
  _running = on;
  document.getElementById('run-btn').disabled  = on;
  // Stop button only active for stoppable runs (investigations), not hunts/inventory
  document.getElementById('stop-btn').disabled = !(on && _stoppable);
  document.getElementById('dot').className = 'live-dot' + (on ? ' running' : '');
  document.getElementById('status-badge').textContent = on ? 'running' : 'idle';
  document.getElementById('status-text').textContent  = on ? 'running...' : 'idle';
  // Show running indicator on Run tab button
  const runTabBtn = document.getElementById('tab-run-btn');
  if (on) runTabBtn.classList.add('running');
  else    runTabBtn.classList.remove('running');
}

function startRun() {
  if (_running) return;
  _stoppable = true;
  const sev   = document.getElementById('severity').value;
  const hours = document.getElementById('hours').value;
  const agent = document.getElementById('agent').value.trim();
  // Switch to Run tab so user sees output
  switchTab('run');
  _liveBuffer = ''; document.getElementById('live-out').innerHTML = '';
  document.getElementById('live-title').textContent = 'Output — running';
  setRunning(true);
  _t0 = Date.now();
  _timer = setInterval(() => {
    const s   = Math.floor((Date.now() - _t0) / 1000);
    const m   = Math.floor(s / 60), sec = s % 60;
    document.getElementById('elapsed').textContent =
      m > 0 ? m + 'm ' + sec + 's' : s + 's';
  }, 1000);
  const p = new URLSearchParams({severity: sev, hours, agent});
  _es = new EventSource('/stream?' + p);
  _liveBuffer = '';
  _es.onmessage = e => {
    if (e.data === '__DONE__') { finish(false); return; }
    _liveBuffer += e.data;
    const out = document.getElementById('live-out');
    // During streaming: plain text with preserved newlines (fast, no broken HTML)
    // After done: re-render with marked for proper formatting
    out.textContent = _liveBuffer;
    out.scrollTop = out.scrollHeight;
  };
  _es.onerror = () => finish(true);
}

function stopRun() {
  fetch('/stop', {method: 'POST'});
  if (_es) { _es.close(); _es = null; }
  clearInterval(_timer);
  setRunning(false);
  document.getElementById('elapsed').textContent = '';
  document.getElementById('live-title').textContent = 'Output — stopped';
  document.getElementById('dot').className = 'live-dot';
  const out = document.getElementById('live-out');
  const note = document.createElement('div');
  note.style.cssText = 'color:#f0883e;font-size:12px;margin-top:8px';
  note.textContent = '■ Stopped by user. (Model inference already in progress '
    + 'may finish in the background but its result is discarded.)';
  out.appendChild(note);
  _loadHistoryData();
}

function finish(err) {
  clearInterval(_timer);
  if (_es) { _es.close(); _es = null; }
  setRunning(false);
  if (err) document.getElementById('dot').className = 'live-dot error';
  document.getElementById('last-run').textContent =
    'completed ' + new Date().toLocaleTimeString();
  document.getElementById('elapsed').textContent = '';
  document.getElementById('live-title').textContent = 'Output';
  // Re-render completed output with markdown
  const out = document.getElementById('live-out');
  if (_liveBuffer && typeof marked !== 'undefined') {
    out.classList.add('md-body');
    out.innerHTML = marked.parse(_liveBuffer);
  }
  // Refresh history list silently so Reports tab is up to date
  _loadHistoryData();
}

// ── History & reports ─────────────────────────────────────────────────────────
let _activeId = null;
let _histData  = [];

function _loadHistoryData() {
  return fetch('/history').then(r => r.json()).then(items => {
    _histData = items;
    _renderHistory();
    return items;
  });
}

function loadHistory() { _loadHistoryData(); }

function _renderHistory() {
  const el = document.getElementById('hist-list');
  if (!_histData.length) {
    el.innerHTML = '<div style="padding:10px;font-size:11px;color:#484f58">No investigations yet.</div>';
    return;
  }
  el.innerHTML = _histData.map(i => {
    const active = i.id === _activeId ? ' active' : '';
    const color  = i.status === 'error' ? '#f85149'
                 : i.status === 'running' ? '#3fb950' : '#484f58';
    const copyBtn = (i.status === 'completed' && i.report)
      ? '<button class="hbtn" data-copy="' + i.id + '" style="color:#8b949e">Copy</button>'
      : '';
    const delBtn = '<button class="hbtn" data-del="' + i.id + '" style="color:#f85149">&#x2715;</button>';
    return '<div class="hi' + active + '" data-id="' + i.id + '">'
      + '<div class="hl">' + esc(i.label) + '</div>'
      + '<div class="hm">'
      + '<span class="ds ' + i.status + '"></span>'
      + '<span>' + i.started + (i.ended ? ' — ' + i.ended : '') + '</span>'
      + '<span style="margin-left:auto;color:' + color + '">' + i.status + '</span>'
      + copyBtn + delBtn
      + '</div></div>';
  }).join('');

  // Attach click handlers after render (avoids all escaping issues)
  el.querySelectorAll('.hi').forEach(div => {
    div.addEventListener('click', () => showReport(div.dataset.id));
  });
  el.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', e => { e.stopPropagation(); copySingle(btn.dataset.copy); });
  });
  el.querySelectorAll('[data-del]').forEach(btn => {
    btn.addEventListener('click', e => { e.stopPropagation(); deleteInv(btn.dataset.del); });
  });
}

function showReport(id) {
  _activeId = id;
  fetch('/history/' + id).then(r => r.json()).then(d => {
    const out    = document.getElementById('report-out');
    const header = document.getElementById('report-header');
    const md = window.marked ? window.marked.parse.bind(window.marked) : (t => t);
    if (d.status === 'running') {
      header.textContent = 'Investigation running — switch to Run tab for live output';
      out.textContent    = 'Report will appear here when the investigation completes.';
    } else {
      header.textContent = d.label || d.id;
      const reportText   = d.report || '[No report available]';
      out.innerHTML      = md(reportText);
      out.scrollTop      = 0;
      const copyBtn = document.getElementById('copy-btn');
      if (copyBtn) copyBtn.style.display = d.report ? 'inline-block' : 'none';
    }
    _renderHistory();
  });
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function copyReport() {
  const text = document.getElementById('report-out').innerText;
  const btn  = document.getElementById('copy-btn');
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
}

function copySingle(id) {
  const item = _histData.find(i => i.id === id);
  if (!item || !item.report) return;
  const btn = document.getElementById('cpybtn-' + id);
  navigator.clipboard.writeText(item.report).then(() => {
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 2000); }
  });
}

function deleteInv(id) {
  if (!confirm('Delete this investigation?')) return;
  fetch('/history/' + id, {method: 'DELETE'})
    .then(r => r.json())
    .then(d => {
      if (d.ok) {
        if (_activeId === id) {
          document.getElementById('report-out').innerHTML = '';
          const ht = document.getElementById('report-header-text');
          if (ht) ht.textContent = 'Select an investigation from the sidebar';
          const cb = document.getElementById('copy-btn');
          if (cb) cb.style.display = 'none';
          _activeId = null;
        }
        _loadHistoryData();
      }
    });
}

function copyLive() {
  const text = _liveBuffer;
  const btn  = document.getElementById('copy-live-btn');
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
}

// ── Context Q&A ───────────────────────────────────────────────────────────────
function askContext() {
  const q   = document.getElementById('ctx-input').value.trim();
  const ans = document.getElementById('ctx-answer');
  const src = document.getElementById('ctx-src');
  const btn = document.getElementById('ask-btn');
  if (!q) return;
  ans.style.display = 'block';
  ans.textContent   = 'Thinking...';
  src.textContent   = '';
  btn.disabled      = true;
  fetch('/context', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({question: q})
  }).then(r => r.json()).then(d => {
    ans.textContent = d.answer || d.error || 'No answer';
    src.textContent = 'Based on ' + (d.sources || 0)
      + ' past investigation' + (d.sources !== 1 ? 's' : '');
    btn.disabled = false;
  }).catch(e => {
    ans.textContent = 'Error: ' + e;
    btn.disabled    = false;
  });
}
document.getElementById('ctx-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') askContext();
});

// ── Scheduler ─────────────────────────────────────────────────────────────────
function updateSched() {
  fetch('/schedule', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      enabled:        document.getElementById('sched-on').checked,
      interval_hours: +document.getElementById('sched-hours').value,
      severity:       +document.getElementById('sched-sev').value,
      hours:          +document.getElementById('hours').value,
      agent:          document.getElementById('agent').value.trim(),
    })
  }).then(r => r.json()).then(d => {
    document.getElementById('sched-status').textContent =
      d.enabled ? 'On — every ' + d.interval_hours + 'h' : 'Off';
  });
}

// ── Background polling ────────────────────────────────────────────────────────
setInterval(_loadHistoryData, 15000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML, model=OLLAMA_MODEL)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Wazuh Correlation Agent UI")
    p.add_argument("--port",     type=int, default=UI_PORT)
    p.add_argument("--host",     type=str, default=os.getenv("UI_HOST", "0.0.0.0"))
    p.add_argument("--log-file", type=str, default=os.getenv("LOG_FILE", ""),
                   dest="log_file")

    args = p.parse_args()

    ST.log_file = args.log_file
    if ST.log_file:
        Path(ST.log_file).parent.mkdir(parents=True, exist_ok=True)

    threading.Thread(target=_scheduler, daemon=True).start()

    print(f"Wazuh Correlation Agent")
    print(f"  UI      : http://{args.host}:{args.port}")
    print(f"  Model   : {OLLAMA_MODEL}")
    print(f"  Log     : {ST.log_file or 'disabled'}")
    print(f"  History : {ST.hist_file}")
    print(f"  Ctrl+C to stop")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
