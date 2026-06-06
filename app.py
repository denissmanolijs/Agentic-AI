
import os, sys, json, queue, threading, time, logging, argparse
from datetime import datetime
from pathlib import Path
from collections import OrderedDict
from flask import Flask, Response, request, render_template_string, jsonify
from flask_cors import CORS

# ── Bootstrap ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correlate as ag        # owns .env loading + config dict C
import agent_tools as agent   # the agentic tool-calling loop

app  = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("app")

# Single config source — all of these come from correlate.C (.env read once there)
AGENTIC_MODEL = ag.C["AGENTIC_MODEL"]
UI_PORT       = ag.C["UI_PORT"]
UI_HOST       = ag.C["UI_HOST"]


# ── Shared state ──────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.lock       = threading.Lock()   # one investigation at a time
        self.log_file   = ""
        self.sched_cfg  = {"enabled": False, "interval_hours": 8, "hours": 24}
        self.sched_wake = threading.Event()
        self.history    = OrderedDict()
        self.hist_lock  = threading.Lock()
        self.hist_file  = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "investigations.json")
        self._load_history()

    def _load_history(self):
        try:
            if Path(self.hist_file).exists():
                for item in json.loads(Path(self.hist_file).read_text()):
                    self.history[item["id"]] = item
                log.info("Loaded %d investigations from history", len(self.history))
        except Exception as e:
            log.warning("Could not load history: %s", e)

    def _save_history(self):
        try:
            items = list(self.history.values())[-50:]   # keep last 50
            Path(self.hist_file).write_text(json.dumps(items, indent=2))
        except Exception as e:
            log.warning("Could not save history: %s", e)

ST = State()


# ──────────────────────────────────────────────────────────────────────────────
#  THE AGENTIC RUN  (shared by /agent and the scheduler)
# ──────────────────────────────────────────────────────────────────────────────
def _run_agentic(question, run_id, q=None):
    """
    Execute one agentic investigation. Streams events into queue `q` (if given)
    as SSE-ready text, and saves the final answer + audit trail to history.
    """
    ag.STOP_FLAG.clear()
    trace_lines = []     # human-readable trace for the live panel
    audit       = []     # structured tool-call record for the report

    def emit(kind, payload):
        # Build a readable line per event kind, push to the live queue.
        line = ""
        if kind == "thinking":
            line = f"\n[thinking] {payload}\n"
        elif kind == "tool_call":
            line = f"\n→ {payload['name']}({json.dumps(payload['args'])})\n"
            audit.append({"tool": payload["name"], "args": payload["args"],
                          "ts": datetime.now().isoformat()})
        elif kind == "tool_result":
            preview = json.dumps(payload["result"])
            if len(preview) > 600:
                preview = preview[:600] + "…"
            line = f"  ← {preview}\n"
        elif kind == "answer":
            line = f"\n\n{'='*60}\nFINAL ASSESSMENT\n{'='*60}\n{payload}\n"
        elif kind == "error":
            line = f"\n[error] {payload}\n"
        if line:
            trace_lines.append(line)
            if q is not None:
                q.put(line)

    final = ""
    try:
        final = agent.run_agent(question, emit=emit)
    except Exception as e:
        log.exception("Agentic run failed")
        if q is not None:
            q.put(f"\n[error] {e}\n")
        final = f"[error: {e}]"

    # Compose the saved report: the verdict, then the audit trail.
    audit_text = "\n".join(
        f"{i+1}. {a['tool']}({json.dumps(a['args'])})" for i, a in enumerate(audit)
    ) or "(no tool calls recorded)"
    report = (f"QUESTION: {question}\n\n{final}\n\n"
              f"{'─'*50}\nTOOL-CALL AUDIT TRAIL ({len(audit)} calls)\n{'─'*50}\n"
              f"{audit_text}")

    with ST.hist_lock:
        if run_id in ST.history:
            ST.history[run_id]["status"] = ("stopped" if ag.STOP_FLAG.is_set()
                                            else "completed")
            ST.history[run_id]["report"] = report
            ST.history[run_id]["ended"]  = datetime.now().strftime("%H:%M")
        while len(ST.history) > 50:
            ST.history.popitem(last=False)
        ST._save_history()

    if q is not None:
        q.put("__DONE__")
    return report


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/agent")
def agent_stream():
    """SSE endpoint: run an agentic investigation, stream the live trace."""
    question = (request.args.get("q") or "").strip()
    if not question:
        def bad():
            yield "data: [No question provided.]\n\n"
            yield "data: __DONE__\n\n"
        return Response(bad(), mimetype="text/event-stream")

    if not ST.lock.acquire(blocking=False):
        def busy():
            yield "data: [An investigation is already running. Wait for it to finish.]\n\n"
            yield "data: __DONE__\n\n"
        return Response(busy(), mimetype="text/event-stream")

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    with ST.hist_lock:
        ST.history[run_id] = {
            "id": run_id, "label": question[:70],
            "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "ended": None, "status": "running", "report": "",
        }

    q = queue.Queue()
    threading.Thread(target=_run_agentic, args=(question, run_id, q),
                     daemon=True).start()

    def generate():
        try:
            # Send the run_id first so the client can link to the report.
            yield f"data: __RUNID__{run_id}\n\n"
            while True:
                try:
                    chunk = q.get(timeout=30)
                except queue.Empty:
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
    ag.STOP_FLAG.set()
    return {"ok": True}


@app.route("/history")
def history():
    with ST.hist_lock:
        items = [{"id": v["id"], "label": v["label"], "started": v["started"],
                  "ended": v["ended"], "status": v["status"],
                  "report": v.get("report", "")}
                 for v in reversed(list(ST.history.values()))]
    return jsonify(items)


@app.route("/history/<run_id>", methods=["GET"])
def get_report(run_id):
    with ST.hist_lock:
        item = ST.history.get(run_id)
    return (jsonify(item) if item else (jsonify({"error": "not found"}), 404))


@app.route("/history/<run_id>", methods=["DELETE"])
def delete_report(run_id):
    with ST.hist_lock:
        if run_id not in ST.history:
            return jsonify({"error": "not found"}), 404
        del ST.history[run_id]
        ST._save_history()
    return jsonify({"ok": True})


@app.route("/schedule", methods=["POST"])
def set_schedule():
    ST.sched_cfg.update(request.get_json() or {})
    ST.sched_wake.set()
    return jsonify(ST.sched_cfg)


@app.route("/status")
def status():
    return jsonify({"running": ST.lock.locked(), "model": AGENTIC_MODEL,
                    "schedule": ST.sched_cfg})


# ── Scheduler ─────────────────────────────────────────────────────────────────
def _scheduler():
    """Fires an agentic triage on a timer: 'perform alert triage on the last N hours'."""
    while True:
        cfg = ST.sched_cfg
        if not cfg["enabled"]:
            ST.sched_wake.wait(60); ST.sched_wake.clear(); continue
        last = getattr(ST, "_last_sched", 0)
        wait = max(0, last + cfg["interval_hours"]*3600 - time.time())
        if wait > 0:
            ST.sched_wake.wait(wait); ST.sched_wake.clear(); continue
        if ST.lock.acquire(blocking=False):
            run_id   = "sched_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            hours    = cfg.get("hours", 24)
            question = f"perform alert triage on the last {hours} hours"
            with ST.hist_lock:
                ST.history[run_id] = {
                    "id": run_id, "label": f"Scheduled — {question}",
                    "started": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "ended": None, "status": "running", "report": "",
                }
            try:
                _run_agentic(question, run_id, q=None)
            finally:
                ST.lock.release()
                ST._last_sched = time.time()


# ── Page ──────────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agentic Security Analyst</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0d1117;color:#e6edf3;
  display:flex;flex-direction:column;height:100vh;overflow:hidden}

/* Header */
header{background:#161b22;border-bottom:1px solid #30363d;
  padding:10px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}
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

.tab{display:none;flex:1;overflow:hidden;flex-direction:column}
.tab.active{display:flex}

/* Run tab */
.run-tab{flex:1;display:flex;flex-direction:column;overflow:hidden}
.controls{padding:14px 20px;border-bottom:1px solid #30363d;flex-shrink:0}
.nl-wrap{position:relative;margin-bottom:10px}
#nl-input{width:100%;background:#0d1117;border:1px solid #388bfd55;
  border-radius:6px;color:#e6edf3;font-size:13px;
  padding:10px 90px 10px 12px;font-family:monospace}
#nl-input:focus{outline:none;border-color:#58a6ff}
#nl-input::placeholder{color:#484f58}
.nl-btn{position:absolute;right:5px;top:50%;transform:translateY(-50%);
  background:#1f6feb;border:none;border-radius:4px;color:#fff;
  cursor:pointer;font-size:12px;padding:6px 14px}
.nl-btn:hover{opacity:.85}
#nl-preview{background:#0d1117;border:1px solid #30363d;border-radius:5px;
  padding:10px 12px;font-size:12px;color:#8b949e;display:none;margin-bottom:8px}
.confirm-q{color:#e6edf3;margin-bottom:8px;word-break:break-word}
.confirm-note{color:#8b949e;font-size:11px;margin-bottom:10px}
.confirm-yes{padding:6px 18px;background:#238636;border:none;border-radius:5px;
  color:#fff;font-size:12px;cursor:pointer;margin-right:8px}
.confirm-yes:hover{background:#2ea043}
.confirm-no{padding:6px 18px;background:#21262d;border:1px solid #30363d;
  border-radius:5px;color:#8b949e;font-size:12px;cursor:pointer}
.confirm-no:hover{color:#e6edf3}
button{border:none;border-radius:5px;cursor:pointer;font-size:12px;
  font-weight:500;padding:7px 16px;transition:opacity .15s}
button:disabled{opacity:.35;cursor:not-allowed}
.btn-stop{background:#da3633;color:#fff}
.btn-stop:hover:not(:disabled){opacity:.85}
.hint{font-size:10px;color:#484f58;margin-top:8px}

.sched-bar{padding:8px 20px;border-bottom:1px solid #30363d;
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
.sched-bar input[type=number]{background:#0d1117;border:1px solid #30363d;
  border-radius:5px;color:#e6edf3;font-size:12px;padding:4px 6px;
  width:52px;font-family:monospace}

/* Live output */
.live-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden}
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
.status-bar{padding:6px 20px;font-size:11px;color:#8b949e;
  border-top:1px solid #21262d;flex-shrink:0;display:flex;
  align-items:center;gap:8px}

/* Reports tab */
.reports-tab{flex:1;display:flex;overflow:hidden}
.reports-sidebar{width:280px;min-width:280px;border-right:1px solid #30363d;
  display:flex;flex-direction:column}
.sb-head{padding:10px 14px;font-size:10px;font-weight:700;color:#8b949e;
  text-transform:uppercase;letter-spacing:.07em;border-bottom:1px solid #30363d}
.hist-list{flex:1;overflow-y:auto;padding:4px}
.hi{padding:8px 10px;border-radius:5px;cursor:pointer;margin-bottom:2px;
  border:1px solid transparent}
.hi:hover{background:#21262d}
.hi.active{background:#1f3a5f;border-color:#1f6feb}
.hl{font-size:12px;color:#e6edf3;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.hm{font-size:10px;color:#8b949e;margin-top:2px;display:flex;gap:5px;align-items:center}
.ds{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.ds.running{background:#3fb950;animation:blink 1.2s infinite}
.ds.completed{background:#3fb950}
.ds.stopped{background:#f0883e}
.ds.error{background:#f85149}
.hbtn{margin-left:5px;font-size:10px;padding:2px 7px;background:#21262d;
  border:1px solid #30363d;border-radius:3px;cursor:pointer}
.report-main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.report-header{padding:10px 18px;border-bottom:1px solid #30363d;
  font-size:12px;font-weight:600;color:#8b949e;flex-shrink:0;
  display:flex;align-items:center;gap:10px}
#report-out{flex:1;padding:16px 20px;overflow-y:auto;font-size:13px;
  line-height:1.75;word-break:break-word;white-space:pre-wrap}
</style>
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
          placeholder="Ask anything — e.g. correlate severity 12 events over the last 20 days, or is data being exfiltrated from my endpoints?"
          onkeydown="if(event.key==='Enter')askConfirm()">
        <button class="nl-btn" onclick="askConfirm()">Run now</button>
      </div>
      <div id="nl-preview"></div>
      <div style="display:flex;gap:6px;align-items:center">
        <button class="btn-stop" id="stop-btn" onclick="stopRun()" disabled>Stop</button>
        <p class="hint" style="margin:0">The agent plans its own investigation, runs Wazuh queries, and reports a verdict. This may take several minutes.</p>
      </div>
    </div>

    <div class="sched-bar">
      <label class="toggle">
        <input type="checkbox" id="sched-on" onchange="updateSched()">
        <span class="slider"></span>
      </label>
      <span class="si">Auto-run triage every</span>
      <input type="number" id="sched-hours" value="8" min="1" max="72"
        onchange="updateSched()">
      <span class="si">hours — over the last</span>
      <input type="number" id="sched-window" value="24" min="1" max="336"
        onchange="updateSched()">
      <span class="si">hours of events</span>
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
      <div id="live-out">Ready. Ask a question above and click Run now.</div>
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
    <div class="reports-sidebar">
      <div class="sb-head">Investigation history</div>
      <div class="hist-list" id="hist-list">
        <div style="padding:10px;font-size:11px;color:#484f58">No investigations yet.</div>
      </div>
    </div>
    <div class="report-main">
      <div class="report-header">
        <span id="report-header-text">Select an investigation from the sidebar</span>
        <button id="copy-btn" onclick="copyReport()"
          style="margin-left:auto;font-size:11px;padding:3px 10px;background:#21262d;
          color:#8b949e;border:1px solid #30363d;border-radius:4px;cursor:pointer;
          display:none">Copy</button>
      </div>
      <div id="report-out"></div>
    </div>
  </div>
</div>

<script>
let _es=null, _running=false, _t0=0, _timer=null, _liveBuffer='',
    _pendingQ=null, _histData=[], _activeId=null, _curRunId=null;

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.hdr-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('tab-' + name + '-btn').classList.add('active');
  if (name === 'reports') loadHistory();
}

// ── Ask → confirm → run ─────────────────────────────────────────────────────
function askConfirm() {
  const q = document.getElementById('nl-input').value.trim();
  if (!q) return;
  if (_running) return;
  _pendingQ = q;
  const p = document.getElementById('nl-preview');
  p.style.display = 'block';
  p.innerHTML =
      '<div class="confirm-q">Run agentic investigation?<br><strong>"'
    + esc(q) + '"</strong></div>'
    + '<div class="confirm-note">The agent will plan and run multiple Wazuh '
    + 'queries. This may take several minutes.</div>'
    + '<button class="confirm-yes" onclick="confirmRun()">Yes, do it</button>'
    + '<button class="confirm-no" onclick="cancelConfirm()">Cancel</button>';
}

function cancelConfirm() {
  _pendingQ = null;
  document.getElementById('nl-preview').style.display = 'none';
}

function confirmRun() {
  const q = _pendingQ;
  document.getElementById('nl-preview').style.display = 'none';
  if (!q) return;
  startAgent(q);
}

function startAgent(question) {
  if (_running) return;
  const out = document.getElementById('live-out');
  out.textContent = '';
  _liveBuffer = '';
  _curRunId   = null;
  document.getElementById('live-title').textContent = 'Investigating';
  document.getElementById('dot').className = 'live-dot running';
  setRunning(true);
  _t0 = Date.now();
  _timer = setInterval(() => {
    document.getElementById('elapsed').textContent =
      Math.floor((Date.now()-_t0)/1000) + 's';
  }, 1000);

  _es = new EventSource('/agent?q=' + encodeURIComponent(question));
  _es.onmessage = (e) => {
    const d = e.data;
    if (d === '__DONE__') { finish(false); return; }
    if (d.startsWith('__RUNID__')) { _curRunId = d.slice(9); return; }
    _liveBuffer += d + '\n';
    out.textContent = _liveBuffer;
    out.scrollTop = out.scrollHeight;
  };
  _es.onerror = () => { finish(true); };
}

function stopRun() {
  fetch('/stop', {method:'POST'});
  if (_es) { _es.close(); _es = null; }
  clearInterval(_timer);
  setRunning(false);
  document.getElementById('elapsed').textContent = '';
  document.getElementById('live-title').textContent = 'Output — stopped';
  document.getElementById('dot').className = 'live-dot';
  const note = document.createElement('div');
  note.style.cssText = 'color:#f0883e;font-size:12px;margin-top:8px';
  note.textContent = '■ Stopped by user. A model step already in progress may '
    + 'finish in the background, but its result is discarded.';
  document.getElementById('live-out').appendChild(note);
  _loadHistoryData();
}

function finish(err) {
  clearInterval(_timer);
  if (_es) { _es.close(); _es = null; }
  setRunning(false);
  document.getElementById('dot').className = err ? 'live-dot error' : 'live-dot';
  document.getElementById('elapsed').textContent = '';
  document.getElementById('live-title').textContent = 'Output';
  document.getElementById('last-run').textContent =
    'completed ' + new Date().toLocaleTimeString();
  _loadHistoryData();
}

function setRunning(on) {
  _running = on;
  document.getElementById('stop-btn').disabled = !on;
  document.getElementById('status-text').textContent = on ? 'investigating…' : 'idle';
  document.getElementById('status-badge').textContent = on ? 'running' : 'idle';
  document.getElementById('tab-run-btn').classList.toggle('running', on);
}

// ── History / Reports ────────────────────────────────────────────────────────
function _loadHistoryData() {
  return fetch('/history').then(r => r.json()).then(items => {
    _histData = items; _renderHistory(); return items;
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
                 : i.status === 'running' ? '#3fb950'
                 : i.status === 'stopped' ? '#f0883e' : '#484f58';
    const copyBtn = (i.report)
      ? '<button class="hbtn" data-copy="' + i.id + '" style="color:#8b949e">Copy</button>' : '';
    const delBtn = '<button class="hbtn" data-del="' + i.id + '" style="color:#f85149">&#x2715;</button>';
    return '<div class="hi' + active + '" data-id="' + i.id + '">'
      + '<div class="hl">' + esc(i.label) + '</div>'
      + '<div class="hm"><span class="ds ' + i.status + '"></span>'
      + '<span>' + i.started + (i.ended ? ' — ' + i.ended : '') + '</span>'
      + '<span style="margin-left:auto;color:' + color + '">' + i.status + '</span>'
      + copyBtn + delBtn + '</div></div>';
  }).join('');
  el.querySelectorAll('.hi').forEach(div =>
    div.addEventListener('click', () => showReport(div.dataset.id)));
  el.querySelectorAll('[data-copy]').forEach(btn =>
    btn.addEventListener('click', e => { e.stopPropagation(); copySingle(btn.dataset.copy); }));
  el.querySelectorAll('[data-del]').forEach(btn =>
    btn.addEventListener('click', e => { e.stopPropagation(); deleteInv(btn.dataset.del); }));
}

function showReport(id) {
  _activeId = id;
  fetch('/history/' + id).then(r => r.json()).then(d => {
    const out = document.getElementById('report-out');
    const hdr = document.getElementById('report-header-text');
    const cb  = document.getElementById('copy-btn');
    if (d.status === 'running') {
      hdr.textContent = 'Investigation running — see the Run tab for live output';
      out.textContent = 'The report will appear here when the investigation completes.';
      if (cb) cb.style.display = 'none';
    } else {
      hdr.textContent = d.label || d.id;
      out.textContent = d.report || '[No report available]';
      out.scrollTop = 0;
      if (cb) cb.style.display = d.report ? 'inline-block' : 'none';
    }
    _renderHistory();
  });
}

function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function copyReport() {
  const t = document.getElementById('report-out').innerText;
  const b = document.getElementById('copy-btn');
  navigator.clipboard.writeText(t).then(() => {
    b.textContent='Copied!'; setTimeout(()=>{b.textContent='Copy';},2000);
  });
}
function copySingle(id) {
  const it = _histData.find(i => i.id === id);
  if (!it || !it.report) return;
  navigator.clipboard.writeText(it.report);
}
function deleteInv(id) {
  if (!confirm('Delete this investigation?')) return;
  fetch('/history/' + id, {method:'DELETE'}).then(r=>r.json()).then(d => {
    if (d.ok) {
      if (_activeId === id) {
        document.getElementById('report-out').textContent = '';
        document.getElementById('report-header-text').textContent =
          'Select an investigation from the sidebar';
        document.getElementById('copy-btn').style.display = 'none';
        _activeId = null;
      }
      _loadHistoryData();
    }
  });
}
function copyLive() {
  const b = document.getElementById('copy-live-btn');
  navigator.clipboard.writeText(_liveBuffer).then(() => {
    b.textContent='Copied!'; setTimeout(()=>{b.textContent='Copy';},2000);
  });
}

// ── Scheduler ────────────────────────────────────────────────────────────────
function updateSched() {
  fetch('/schedule', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      enabled:        document.getElementById('sched-on').checked,
      interval_hours: +document.getElementById('sched-hours').value,
      hours:          +document.getElementById('sched-window').value,
    })
  }).then(r=>r.json()).then(d => {
    document.getElementById('sched-status').textContent =
      d.enabled ? 'On — every ' + d.interval_hours + 'h' : 'Off';
  });
}

setInterval(_loadHistoryData, 15000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML, model=AGENTIC_MODEL)


PID_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.pid")
LOG_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.log")

def _read_pid():
    try:
        pid = int(Path(PID_FILE).read_text().strip())
        os.kill(pid, 0)        # raises if not running
        return pid
    except Exception:
        return None

def _serve(args):
    """Actually start the Flask server (foreground in this process)."""
    ST.log_file = args.log_file
    threading.Thread(target=_scheduler, daemon=True).start()
    print("Wazuh Agentic Security Analyst")
    print(f"  UI      : http://{args.host}:{args.port}")
    print(f"  Model   : {AGENTIC_MODEL}")
    print(f"  History : {ST.hist_file}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

def main():
    p = argparse.ArgumentParser(description="Wazuh Agentic Security Analyst")
    p.add_argument("command", nargs="?", default="run",
                   choices=["run", "start", "stop", "restart", "status"],
                   help="run=foreground (default), start=background, "
                        "stop=stop background, restart, status")
    p.add_argument("--port", type=int, default=UI_PORT)
    p.add_argument("--host", default=UI_HOST)
    p.add_argument("--log-file", default="")
    args = p.parse_args()

    # ── stop ──────────────────────────────────────────────────────────────────
    if args.command == "stop":
        pid = _read_pid()
        if not pid:
            print("Not running (no live PID file).")
            Path(PID_FILE).unlink(missing_ok=True)
            return
        import signal as _sig
        os.kill(pid, _sig.SIGTERM)
        for _ in range(20):                 # wait up to ~5s for clean exit
            time.sleep(0.25)
            try: os.kill(pid, 0)
            except OSError: break
        else:
            os.kill(pid, _sig.SIGKILL)       # force if it did not stop
        Path(PID_FILE).unlink(missing_ok=True)
        print(f"Stopped (PID {pid}).")
        return

    # ── status ────────────────────────────────────────────────────────────────
    if args.command == "status":
        pid = _read_pid()
        print(f"Running (PID {pid}). UI: http://{args.host}:{args.port}"
              if pid else "Not running.")
        return

    # ── restart ─────────────────────────────────────────────────────────────--
    if args.command == "restart":
        pid = _read_pid()
        if pid:
            import signal as _sig
            os.kill(pid, _sig.SIGTERM); time.sleep(1)
            try: os.kill(pid, 0); os.kill(pid, _sig.SIGKILL)
            except OSError: pass
            Path(PID_FILE).unlink(missing_ok=True)
            print(f"Stopped old instance (PID {pid}).")
        args.command = "start"   # fall through to start

    # ── start (background) ─────────────────────────────────────────────────────
    if args.command == "start":
        if _read_pid():
            print(f"Already running (PID {_read_pid()}). Use 'stop' or 'restart'.")
            return
        # Re-launch this script in 'run' mode as a detached child, logging to file.
        import subprocess
        logf = open(args.log_file or LOG_FILE, "a")
        child = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "run",
             "--port", str(args.port), "--host", args.host],
            stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
            start_new_session=True)          # detach from this terminal
        Path(PID_FILE).write_text(str(child.pid))
        time.sleep(1.5)
        if _read_pid():
            print(f"Started in background (PID {child.pid}).")
            print(f"  UI   : http://{args.host}:{args.port}")
            print(f"  Log  : {args.log_file or LOG_FILE}")
            print(f"  Stop : python3 {os.path.basename(__file__)} stop")
        else:
            print("Failed to start — check the log file.")
        return

    # ── run (foreground, default) ──────────────────────────────────────────────
    # When launched as a background child we are the server process; record our
    # own PID so 'stop' can find us even if the parent already exited.
    Path(PID_FILE).write_text(str(os.getpid()))
    import atexit, signal as _sig
    atexit.register(lambda: Path(PID_FILE).unlink(missing_ok=True))
    _sig.signal(_sig.SIGTERM, lambda *a: (_ for _ in ()).throw(SystemExit))
    try:
        _serve(args)
    finally:
        Path(PID_FILE).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
