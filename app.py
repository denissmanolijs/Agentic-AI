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
    t   = text.lower().strip()
    out = {
        "severity": int(os.getenv("MIN_SEVERITY", 7)),
        "hours":    int(os.getenv("LOOK_BACK_HOURS", 24)),
        "agent":    "",
        "notes":    [],
    }
    # Agent
    m = re.search(r"\bagent\s+(?:id\s+)?(\d{1,3})\b", t)
    if m:
        out["agent"] = m.group(1).zfill(3)
        out["notes"].append(f"agent {out['agent']}")
    elif re.search(r"\ball\s+agents?\b|\bevery\s+agent\b", t):
        out["notes"].append("all agents")

    # Time
    m = re.search(r"(?:past|last|for the past|in the last)\s+(\d+)\s*(h\b|hr\b|hour|hours)", t)
    if m:
        out["hours"] = int(m.group(1))
    else:
        m = re.search(r"(\d+)\s*(h\b|hr\b|hours?)", t)
        if m:          out["hours"] = int(m.group(1))
        elif "week"   in t: out["hours"] = 168
        elif "today"  in t: out["hours"] = 24
        elif re.search(r"last\s+hour|past\s+hour|this\s+hour", t):
            out["hours"] = 1
    out["notes"].append(f"last {out['hours']}h")

    # Severity
    m = re.search(r"(?:severity|level)\s*(\d+)", t)
    if m:
        out["severity"] = int(m.group(1))
    else:
        if   "critical" in t: out["severity"] = 12
        elif "high"     in t: out["severity"] = 10
        elif "medium"   in t: out["severity"] = 7
        elif re.search(r"\blow\b|\ball\b|\beverything\b|\bany\b", t):
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
    return jsonify(parse_nl(request.get_json().get("text", "")))


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
                  "status": v["status"]}
                 for v in reversed(list(ST.history.values()))]
    return jsonify(items)


@app.route("/history/<run_id>")
def get_report(run_id):
    with ST.hist_lock:
        item = ST.history.get(run_id)
    if not item:
        return jsonify({"error": "not found"}), 404
    return jsonify(item)


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
    question = data.get("question", "").strip()
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
<title>Wazuh Correlation Agent</title>
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
  line-height:1.7;white-space:pre-wrap;word-break:break-word}
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
  line-height:1.75;white-space:pre-wrap;word-break:break-word}

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
</style>
</head>
<body>

<header>
  <h1>Wazuh Correlation Agent</h1>
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
          placeholder="e.g. check agent 000 for high severity events last 24 hours — press Enter to parse">
        <button class="nl-btn" onclick="parseNL()">Parse</button>
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
          <button class="btn-run" id="run-btn" onclick="startRun()">Run now</button>
          <button class="btn-stop" id="stop-btn" onclick="stopRun()" disabled>Stop</button>
        </div>
      </div>
      <p class="hint">Type a natural language request and press Enter, or fill the parameters manually.</p>
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
        <option value="3">3 - informational</option>
        <option value="5">5 - user errors</option>
        <option value="7" selected>7 - bad word/sig</option>
        <option value="10">10 - multiple errors</option>
        <option value="12">12 - high importance</option>
        <option value="14">14 - security event</option>
        <option value="15">15 - exploit successful</option>
      </select>
      <span class="si" id="sched-status" style="margin-left:4px">Off</span>
    </div>

    <div class="live-wrap">
      <div class="live-header">
        <div class="live-dot" id="dot"></div>
        <span class="live-title" id="live-title">Output</span>
        <span class="elapsed" id="elapsed"></span>
      </div>
      <div id="live-out">Ready. Configure parameters above and click Run now.</div>
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
      <div class="report-header" id="report-header">
        Select an investigation from the sidebar
      </div>
      <div id="report-out">
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
function parseNL() {
  const text = document.getElementById('nl-input').value.trim();
  if (!text) return;
  fetch('/parse', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text})})
  .then(r => r.json()).then(d => {
    const p = document.getElementById('nl-preview');
    p.style.display = 'block';
    p.innerHTML = 'Understood: <strong>' + d.summary + '</strong>'
      + '&nbsp;&nbsp;<button class="nl-btn" style="position:static;transform:none" '
      + 'onclick="applyNL(' + d.severity + ',' + d.hours + ',\'' + d.agent + '\')">'
      + 'Run this</button>'
      + '&nbsp;<button class="nl-btn" style="position:static;transform:none;'
      + 'background:#21262d;border:1px solid #30363d" '
      + 'onclick="document.getElementById(\'nl-preview\').style.display=\'none\'">Edit</button>';
  });
}
function applyNL(sev, hrs, agent) {
  document.getElementById('severity').value = sev;
  document.getElementById('hours').value    = hrs;
  document.getElementById('agent').value    = agent;
  document.getElementById('nl-preview').style.display = 'none';
  startRun();
}
document.getElementById('nl-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') parseNL();
});

// ── Run control ───────────────────────────────────────────────────────────────
let _es=null, _running=false, _t0=0, _timer=null;

function setRunning(on) {
  _running = on;
  document.getElementById('run-btn').disabled  = on;
  document.getElementById('stop-btn').disabled = !on;
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
  const sev   = document.getElementById('severity').value;
  const hours = document.getElementById('hours').value;
  const agent = document.getElementById('agent').value.trim();
  // Switch to Run tab so user sees output
  switchTab('run');
  document.getElementById('live-out').textContent = '';
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
  _es.onmessage = e => {
    if (e.data === '__DONE__') { finish(false); return; }
    const out = document.getElementById('live-out');
    out.textContent += e.data;
    out.scrollTop = out.scrollHeight;
  };
  _es.onerror = () => finish(true);
}

function stopRun() {
  fetch('/stop', {method: 'POST'});
  finish(false);
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
  el.innerHTML = _histData.map(i =>
    '<div class="hi' + (i.id === _activeId ? ' active' : '') + '" '
    + 'onclick="showReport(\'' + i.id + '\')">'
    + '<div class="hl">' + esc(i.label) + '</div>'
    + '<div class="hm">'
    + '<span class="ds ' + i.status + '"></span>'
    + '<span>' + i.started + (i.ended ? ' — ' + i.ended : '') + '</span>'
    + '<span style="margin-left:auto;color:'
    + (i.status==='error' ? '#f85149' : i.status==='running' ? '#3fb950' : '#484f58')
    + '">' + i.status + '</span>'
    + '</div></div>'
  ).join('');
}

function showReport(id) {
  _activeId = id;
  fetch('/history/' + id).then(r => r.json()).then(d => {
    const out    = document.getElementById('report-out');
    const header = document.getElementById('report-header');
    if (d.status === 'running') {
      header.textContent = 'Investigation running — switch to Run tab for live output';
      out.textContent    = 'Report will appear here when the investigation completes.';
    } else {
      header.textContent = d.label || d.id;
      out.textContent    = d.report || '[No report available]';
      out.scrollTop      = 0;
    }
    _renderHistory();
  });
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
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