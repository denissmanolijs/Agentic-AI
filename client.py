import os, sys, json, argparse, requests, urllib3, logging, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
import ollama

urllib3.disable_warnings()

# -- Config --------------------------------------------------------------------
def _env(p=".env"):
    if Path(p).exists():
        for line in Path(p).read_text().splitlines():
            if line.strip() and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_env()

C = {
    "HOST":    os.getenv("WAZUH_HOST",    "https://localhost:55000"),
    "USER":    os.getenv("WAZUH_USER",    "wazuh-agent"),
    "PASSWD":  os.getenv("WAZUH_PASS",    "wazuh"),
    "IX_HOST": os.getenv("INDEXER_HOST",  "https://localhost:9200"),
    "IX_USER": os.getenv("INDEXER_USER",  "admin"),
    "IX_PASS": os.getenv("INDEXER_PASS",  "admin"),
    "OL_HOST": os.getenv("OLLAMA_HOST",   "http://localhost:11434"),
    "AGENTIC_MODEL": os.getenv("OLLAMA_MODEL", "qwen3"),
    "AGENTIC_MAX_STEPS": int(os.getenv("AGENTIC_MAX_STEPS", "18")),
    "UI_PORT": int(os.getenv("UI_PORT", "5000")),
    "UI_HOST": os.getenv("UI_HOST", "0.0.0.0"),
    # Email delivery (all optional — leave blank to disable)
    "SMTP_HOST": os.getenv("SMTP_HOST", ""),
    "SMTP_PORT": int(os.getenv("SMTP_PORT", "587")),
    "SMTP_USER": os.getenv("SMTP_USER", ""),
    "SMTP_PASS": os.getenv("SMTP_PASS", ""),
    "SMTP_FROM": os.getenv("SMTP_FROM", ""),
    "SMTP_TO":   os.getenv("SMTP_TO",   ""),
}
SSL     = os.getenv("WAZUH_SSL","false").lower() == "true"
MIN_SEV = int(os.getenv("MIN_SEVERITY","3"))
HOURS   = int(os.getenv("LOOK_BACK_HOURS","24"))

# -- Logger --------------------------------------------------------------------
def _setup_logger(debug=False):
    log = logging.getLogger("client")
    log.setLevel(logging.DEBUG if debug else logging.WARNING)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", datefmt="%H:%M:%S")
    sh  = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if debug else logging.WARNING)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if debug:
        fh = logging.FileHandler("client.log", mode="a")
        fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
        log.addHandler(fh)
    return log

log = _setup_logger()
_tok, _tok_exp = None, 0
def _now():    return datetime.now(timezone.utc)
def _since(h): return (_now()-timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
NL = "\n"

# -- API helpers ---------------------------------------------------------------
def _auth():
    global _tok, _tok_exp
    if not _tok or time.time() >= _tok_exp-60:
        # Wazuh's authenticate endpoint can intermittently 500 under load —
        # retry a few times with backoff before giving up.
        last_err = None
        for attempt in range(4):
            try:
                r = requests.post(f"{C['HOST']}/security/user/authenticate",
                                  auth=(C['USER'],C['PASSWD']), verify=SSL, timeout=10)
                if r.status_code == 500:
                    last_err = "500 from authenticate endpoint"
                    time.sleep(1.5 * (attempt + 1))
                    continue
                r.raise_for_status()
                _tok, _tok_exp = r.json()["data"]["token"], time.time()+890
                return {"Authorization": f"Bearer {_tok}"}
            except requests.exceptions.RequestException as e:
                last_err = str(e)
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"Wazuh auth failed after retries: {last_err}")
    return {"Authorization": f"Bearer {_tok}"}

def wget(path, params=None):
    t0 = time.perf_counter()
    try:
        r = requests.get(f"{C['HOST']}{path}", headers=_auth(),
                         params=params, verify=SSL, timeout=15)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot reach Wazuh at {C['HOST']}")
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Wazuh timeout on {path}")
    ms = int((time.perf_counter()-t0)*1000)
    if r.status_code in (400,404):
        log.debug("GET %s -> %d", path, r.status_code)
        return {"affected_items":[],"total_affected_items":0,f"_{r.status_code}":True}
    if r.status_code == 401: raise RuntimeError(f"401 {path} -- check token/permissions")
    if r.status_code == 403: raise RuntimeError(f"403 {path} -- add permission to policy")
    r.raise_for_status()
    log.debug("GET %s -> %dms", path, ms)
    return r.json().get("data",{})

def _ix_post(body, index="wazuh-alerts-*"):
    try:
        r = requests.post(f"{C['IX_HOST']}/{index}/_search",
                          auth=(C['IX_USER'],C['IX_PASS']),
                          json=body, verify=SSL, timeout=20)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot reach indexer at {C['IX_HOST']}")
    if r.status_code == 401: raise RuntimeError("Indexer 401 -- check credentials")
    if r.status_code == 403: raise RuntimeError("Indexer 403 -- missing cluster_composite_ops_ro")
    if r.status_code == 404: return None
    r.raise_for_status()
    return r.json()

def ix_search(q, size=30, sort=None, index="wazuh-alerts-*"):
    body = {"size":size,"query":q}
    if sort: body["sort"]=sort
    t0 = time.perf_counter()
    res = _ix_post(body, index)
    if not res: return {"total":0,"hits":[]}
    hits = res["hits"]
    log.debug("SEARCH -> %dms hits=%d", int((time.perf_counter()-t0)*1000),
              hits["total"]["value"])
    return {"total":hits["total"]["value"],"hits":[h["_source"] for h in hits["hits"]]}

def ix_agg(q, aggs):
    t0 = time.perf_counter()
    res = _ix_post({"size":0,"query":q,"aggs":aggs})
    if not res: return {}
    log.debug("AGG -> %dms", int((time.perf_counter()-t0)*1000))
    return res.get("aggregations",{})

# -- Host inventory (used by the agentic get_inventory tool) -------------------
def inventory(kind, agent_id):
    """
    Raw host inventory via syscollector/syscheck. The caller (the LLM,
    via the get_inventory tool) inspects the names/ports/paths and decides
    what is unusual for the host.
    kind: "packages" | "ports" | "processes" | "files"
    """
    if not agent_id:
        return {"error": "Inventory queries require an agent ID"}
    aid = str(agent_id).zfill(3)

    try:
        if kind == "ports":
            r     = wget(f"/syscollector/{aid}/ports", {"limit": 200})
            items = r.get("affected_items", [])
            rows  = [{"port":    p.get("local", {}).get("port"),
                      "protocol": p.get("protocol", ""),
                      "state":    p.get("state", ""),
                      "process":  p.get("process", "?")} for p in items]
            return {"kind": "ports", "agent": aid,
                    "count": len(rows), "rows": rows}

        elif kind == "processes":
            r     = wget(f"/syscollector/{aid}/processes", {"limit": 300})
            items = r.get("affected_items", [])
            rows  = [{"name": p.get("name", ""),
                      "pid":  p.get("pid", ""),
                      "ppid": p.get("ppid", ""),
                      "cmd":  (p.get("cmd", "") or p.get("command", ""))[:160]}
                     for p in items]
            return {"kind": "processes", "agent": aid,
                    "count": len(rows), "rows": rows}

        elif kind == "packages":
            r     = wget(f"/syscollector/{aid}/packages", {"limit": 500})
            items = r.get("affected_items", [])
            rows  = [{"name":    p.get("name", ""),
                      "version": p.get("version", ""),
                      "vendor":  p.get("vendor", "")} for p in items]
            return {"kind": "packages", "agent": aid,
                    "count": len(rows), "rows": rows}

        elif kind == "files":
            r     = wget(f"/syscheck/{aid}", {"limit": 200})
            items = r.get("affected_items", [])
            rows  = [{"file":  f.get("file", ""),
                      "mtime": str(f.get("mtime", "") or f.get("date", ""))[:19],
                      "hash":  (f.get("sha256", "") or f.get("sha1", ""))[:32]}
                     for f in items]
            return {"kind": "files", "agent": aid,
                    "count": len(rows), "rows": rows}

        else:
            return {"error": f"Unknown inventory kind: {kind}"}

    except Exception as e:
        return {"error": str(e), "kind": kind, "agent": aid}


# -- Rule baseline frequency (used by the agentic get_rule_frequency tool) -----
def _rule_baseline_freq(rule_groups, baseline_days=30):
    """How often does this rule group fire over the baseline window?
    Used for rarity scoring — common rules get a noise penalty.
    Returns events-per-day rate."""
    since = (datetime.now(timezone.utc) - timedelta(days=baseline_days)).isoformat()
    q = {"bool":{"must":[{"range":{"timestamp":{"gte":since}}},
                         {"match":{"rule.groups":rule_groups}}]}}
    try:
        agg = ix_agg(q, {"c":{"value_count":{"field":"rule.level"}}})
        total = agg.get("c",{}).get("value",0)
        return total / max(baseline_days,1)
    except Exception:
        return 0.0

# -- Stop flag (set by the UI Stop button; checked inside the agentic loop) ----
import threading as _threading
STOP_FLAG = _threading.Event()

if __name__ == "__main__":
    # client.py is a library for app.py / agent_tools.py — it has no CLI.
    print("client.py is a data-layer module; run app.py instead.")