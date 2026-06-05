"""
correlate.py -- Wazuh Correlation Agent
Run: python3 correlate.py [--severity N] [--hours N] [--agent ID] [--debug]
"""
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
    "MODEL":   os.getenv("OLLAMA_MODEL",  "qwen2.5:3b"),
    "OL_HOST": os.getenv("OLLAMA_HOST",   "http://localhost:11434"),
}
SSL     = os.getenv("WAZUH_SSL","false").lower() == "true"
MIN_SEV = int(os.getenv("MIN_SEVERITY","3"))
HOURS   = int(os.getenv("LOOK_BACK_HOURS","24"))

# -- Logger --------------------------------------------------------------------
def _setup_logger(debug=False):
    log = logging.getLogger("correlate")
    log.setLevel(logging.DEBUG if debug else logging.WARNING)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", datefmt="%H:%M:%S")
    sh  = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if debug else logging.WARNING)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if debug:
        fh = logging.FileHandler("correlate.log", mode="a")
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
        r = requests.post(f"{C['HOST']}/security/user/authenticate",
                          auth=(C['USER'],C['PASSWD']), verify=SSL, timeout=10)
        r.raise_for_status()
        _tok, _tok_exp = r.json()["data"]["token"], time.time()+890
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

# -- Deduplication config ------------------------------------------------------
# Groups to exclude from investigation
# NOTE: "ossec" was removed — Wazuh port/netstat alerts use this group
# NOTE: "wazuh" was removed — agent start/stop events use this group
SKIP = {"sca","policy_changed","gpg_no_pubkey",
        "agent_restarting","audit_selinux","audit","syslog"}

CANONICAL = {
    "syscheck_file":"syscheck","syscheck_entry_modified":"syscheck",
    "syscheck_entry_added":"syscheck","syscheck_entry_deleted":"syscheck",
    "authentication_failed":"authentication","authentication_success":"authentication",
    "invalid_login":"authentication","pam":"authentication",
    "access_control":"authentication","win_authentication_success":"authentication",
    "windows_security":"authentication",
    "sysmon_eid1_detections":"sysmon","sysmon_eid7_detections":"sysmon",
    "sysmon_eid10_detections":"sysmon","sysmon_eid11_detections":"sysmon",
    "win_evt_channel":"windows","windows_system":"windows",
    "netstat":"network_changes",
    "ossec":"network_changes",   # Wazuh port/netstat monitoring alerts
}

# -- Fetch & deduplicate alerts ------------------------------------------------
def fetch_alerts(since, min_sev, agent_id=None):
    must = [{"range":{"rule.level":{"gte":min_sev}}},
            {"range":{"timestamp":{"gte":since}}}]
    if agent_id: must.append({"term":{"agent.id":agent_id}})
    must_not = ([{"match":{"rule.groups":g}} for g in ["sca","policy_changed"]] +
                [{"match":{"rule.description":d}} for d in ["CIS Benchmark","SCA summary"]])
    q = {"bool":{"must":must,"must_not":must_not}}

    aggs = ix_agg(q, {
        "total":   {"value_count":{"field":"rule.level"}},
        "by_group":{"terms":{"field":"rule.groups","size":25,
                             "order":{"max_lv":"desc"}},
                    "aggs":{"max_lv":   {"max":{"field":"rule.level"}},
                            "count":    {"value_count":{"field":"rule.level"}},
                            "agents":   {"terms":{"field":"agent.name","size":3}},
                            "tactics":  {"terms":{"field":"rule.mitre.tactic","size":3}},
                            "top_rules":{"terms":{"field":"rule.description","size":3}},
                            "sample":   {"top_hits":{"size":1,
                                         "sort":[{"rule.level":{"order":"desc"}}],
                                         "_source":["timestamp","agent.id","agent.name",
                                         "data.srcip","data.srcuser","full_log",
                                         "syscheck.path","rule.description"]}}}},
        "dist":{"range":{"field":"rule.level","ranges":[
            {"key":"low (3-6)",     "from":3, "to":7},
            {"key":"medium (7-9)", "from":7, "to":10},
            {"key":"high (10-12)","from":10,"to":13},
            {"key":"critical (13+)","from":13}]}}
    })

    total = aggs.get("total",{}).get("value",0)
    dist  = {b["key"]:b["doc_count"]
             for b in aggs.get("dist",{}).get("buckets",[]) if b["doc_count"]}
    raw = []
    for b in aggs.get("by_group",{}).get("buckets",[]):
        g   = CANONICAL.get(b["key"], b["key"])
        if g in SKIP: continue
        src = b.get("sample",{}).get("hits",{}).get("hits",[{}])[0].get("_source",{})
        raw.append({
            "rule":    src.get("rule",{}).get("description",g) if src else g,
            "group":   g,
            "covered": [x["key"] for x in b.get("top_rules",{}).get("buckets",[])],
            "level":   int(b.get("max_lv",{}).get("value",0)),
            "count":   int(b.get("count",{}).get("value",0)),
            "agents":  [x["key"] for x in b.get("agents",{}).get("buckets",[])],
            "agent_id":src.get("agent",{}).get("id","") if src else "",
            "tactics": [x["key"] for x in b.get("tactics",{}).get("buckets",[])],
            "ts":      src.get("timestamp","")[:19] if src else "",
            "src_ip":  src.get("data",{}).get("srcip","") if src else "",
            "src_user":src.get("data",{}).get("srcuser","") if src else "",
            "log":     src.get("full_log","")[:200] if src else "",
            "filepath":src.get("syscheck",{}).get("path","") if src else "",
        })
    merged = {}
    for a in raw:
        key = (a["group"],a["agent_id"])
        if key not in merged or a["level"] > merged[key]["level"]:
            merged[key] = a
        else:
            merged[key]["count"] += a["count"]
    return total, dist, sorted(merged.values(), key=lambda x:(-x["level"],-x["count"]))

# -- Attack chain --------------------------------------------------------------
def _event_text(e):
    return " ".join([e.get("rule",""),e.get("log",""),e.get("cmd",""),
                     e.get("image",""),e.get("parent",""),
                     e.get("target",""),e.get("regkey","")]).lower()

def get_chain(agent_id, ts, window=30):
    try:
        t = datetime.fromisoformat(ts.replace("Z","+00:00"))
    except Exception:
        t = _now()
    bef = (t-timedelta(minutes=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    aft = (t+timedelta(minutes=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts0 = t.strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"  [indexer] Fetching event timeline for agent {agent_id} "
          f"({bef[11:16]} to {aft[11:16]})...")
    raw = ix_search({"bool":{"must":[{"term":{"agent.id":agent_id}},
                                      {"range":{"timestamp":{"gte":bef,"lte":aft}}}]}},
                    size=60, sort=[{"timestamp":{"order":"asc"}}])
    print(f"  [indexer] Found {raw['total']} events in timeline")
    events = []
    for h in raw["hits"]:
        et  = h.get("timestamp","")[:19]
        win = h.get("data",{}).get("win",{}).get("eventdata",{})
        events.append({
            "pos":    "BEFORE" if et<ts0[:19] else ("AFTER" if et>ts0[:19] else "TRIGGER"),
            "ts":     et, "level":  h.get("rule",{}).get("level",0),
            "rule":   h.get("rule",{}).get("description",""),
            "tactic": h.get("rule",{}).get("mitre",{}).get("tactic",[]),
            "src_ip": h.get("data",{}).get("srcip",""),
            "log":    h.get("full_log","")[:150],
            "cmd":    win.get("commandLine","")[:120],
            "image":  win.get("image","").split("\\")[-1],
            "parent": win.get("parentImage","").split("\\")[-1],
            "target": win.get("targetFileName","")[-80:],
            "regkey": win.get("targetObject","")[-80:],
            "user":   win.get("user",""),
        })

    bev = [e for e in events if e["pos"]=="BEFORE"]
    aev = [e for e in events if e["pos"]=="AFTER"]
    tactics  = list({t for e in events for t in e["tactic"]})
    src_ips  = list({e["src_ip"] for e in events if e["src_ip"]})
    fails    = [e for e in bev if any(w in e["rule"].lower() for w in ["fail","invalid","denied"])]
    ok       = [e for e in aev if any(w in e["rule"].lower() for w in ["accept","success","opened"])]
    fim_b    = [e for e in bev if any(w in e["rule"].lower() for w in ["integrity","file","syscheck"])]
    proc_a   = [e for e in aev if any(w in e["rule"].lower() for w in ["process","command"])]

    patterns = []
    if len(fails)>=5:
        ext = [i for i in src_ips if not i.startswith(("10.","192.168.","172."))]
        patterns.append(f"{len(fails)} auth failures "+("EXTERNAL IP" if ext else "internal IP"))
    if fails and ok:        patterns.append("Auth failures followed by success")
    if fim_b and proc_a:    patterns.append("File change before trigger + process after")
    if len(set(tactics))>=3:patterns.append(f"Multiple MITRE tactics: {tactics}")

    return {"total":len(events),"before":bev[-8:],"after":aev[:8],
            "patterns":patterns,"tactics":tactics,"src_ips":src_ips,
            "all_events":events}

# -- Behavior detection --------------------------------------------------------
BEHAVIORS = {
    "wmi_execution":     (["wmiprvse","wbem"],            ["wmiprvse.exe"]),
    "psexec":            (["psexec","psexesvc"],           ["psexesvc.exe"]),
    "lateral_smb":       (["admin$","c$ share","ipc$"],   []),
    "credential_dump":   (["lsass","secretsdump","hashdump","ntds","sam database",
                           "credential dump"],             ["lsass.exe"]),
    "pass_the_hash":     (["pass-the-hash","ntlm","pth"], []),
    "powershell":        (["powershell","encodedcommand","invoke-expression"],
                                                           ["powershell.exe","pwsh.exe"]),
    "script_drop":       (["scripting file","vbs","bat file","temp","appdata"],
                                                           ["wscript.exe","cscript.exe"]),
    "process_injection": (["process inject","hollowing","reflective"], []),
    "persistence":       (["service creat","scheduled task","registry run","autorun"],
                                                           ["schtasks.exe"]),
    "fim_change":        (["integrity checksum","file deleted","file added","syscheck"], []),
    "port_change":       (["port opened","port closed","netstat"],                       []),
    "defense_evasion":   (["log clear","vssadmin","bcdedit","wevtutil","shadow copy"],  []),
    "exploit":           (["cve-","exploit","printnightmare","spoolsv","eternalblue"],   []),
}

def detect_behaviors(events):
    found = {}
    texts = [(e, _event_text(e)) for e in events]
    for name,(rkws,pkws) in BEHAVIORS.items():
        hits = [e for e,t in texts if any(k in t for k in rkws+[p.lower() for p in pkws])]
        if hits:
            conf = "high" if pkws and any(any(p.lower() in _event_text(e)
                                              for p in pkws) for e in hits) else "medium"
            found[name] = {"confidence":conf, "count":len(hits), "events":hits[:3]}
    return found

def fmt_behaviors(beh):
    if not beh: return "  none detected"
    return NL.join(f"  [{b['confidence'].upper():6}] {name.replace('_',' ')} ({b['count']} events)"
                   for name,b in sorted(beh.items(), key=lambda x:-x[1]["count"]))

# -- Chain-driven evidence selection ------------------------------------------
SUSP_PORTS = {4444:"Metasploit",4445:"reverse shell",9001:"C2",
              6666:"backdoor",1337:"backdoor",8140:"Puppet Master"}

def _fmt_ports(items):
    return NL.join(
        f"  {p.get('local',{}).get('port'):6}  {p.get('protocol',''):5}  "
        f"{p.get('state',''):12}  {p.get('process','?')}"
        + (" [!] "+SUSP_PORTS[p.get("local",{}).get("port")]
           if p.get("local",{}).get("port") in SUSP_PORTS else "")
        for p in items) or "  none"

def _fmt_sysmon(hits):
    lines = []
    for h in hits:
        win  = h.get("data",{}).get("win",{}).get("eventdata",{})
        line = f"  {h.get('timestamp','')[:19]}  {h.get('rule',{}).get('description','')[:70]}"
        for k,label in [("commandLine","cmd"),("image","process"),
                         ("parentImage","parent"),("targetFileName","file"),
                         ("targetObject","regkey"),("user","user")]:
            val = win.get(k,"")
            if val:
                val = val.split("\\")[-1] if k in ("image","parentImage") else val[-80:]
                line += f"\n    {label:7}: {val}"
        if not any(win.get(k) for k in ("commandLine","image","targetFileName","targetObject")):
            if h.get("full_log"): line += f"\n    log    : {h['full_log'][:150]}"
        lines.append(line)
    return NL.join(lines) or "  none"

def select_enrichment(behaviors, aid, since):
    ev = {}

    # Always: ports
    try:
        print(f"  [server api] GET /syscollector/{aid}/ports — open ports and listening services")
        ports = wget(f"/syscollector/{aid}/ports")
        ev["CURRENT_OPEN_PORTS"] = _fmt_ports(ports.get("affected_items",[]))
    except Exception as e:
        ev["CURRENT_OPEN_PORTS"] = f"  unavailable: {e}"

    # Credential dump or lateral movement -> auth timeline + processes
    if any(b in behaviors for b in ["credential_dump","pass_the_hash",
                                     "lateral_smb","wmi_execution","psexec"]):
        try:
            print(f"  [indexer] Querying authentication timeline for agent {aid}...")
            auth = ix_search({"bool":{"must":[
                {"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}},
                {"bool":{"should":[{"match":{"rule.groups":g}} for g in
                    ["authentication","sshd","sudo","pam",
                     "windows_security","win_authentication_success"]]}}]}},
                size=30, sort=[{"timestamp":{"order":"asc"}}])
            lines = []
            for h in auth["hits"]:
                evd  = h.get("data",{}).get("win",{}).get("eventdata",{})
                line = (f"  {h.get('timestamp','')[:19]}  "
                        f"[{h.get('rule',{}).get('level',0)}] "
                        f"{h.get('rule',{}).get('description','')[:55]}")
                if h.get("data",{}).get("srcip"): line += f"  src={h['data']['srcip']}"
                if evd.get("logonType"):           line += f"  logon={evd['logonType']}"
                if evd.get("authenticationPackageName"):
                    line += f"  auth={evd['authenticationPackageName']}"
                lines.append(line)
            ev["AUTH_TIMELINE"] = NL.join(lines) or "  none"
        except Exception as e:
            ev["AUTH_TIMELINE"] = f"  unavailable: {e}"

        try:
            print(f"  [server api] GET /syscollector/{aid}/processes — checking for credential dump tools")
            procs = wget(f"/syscollector/{aid}/processes",{"limit":100})
            items = procs.get("affected_items",[])
            tools = [p for p in items if any(k in (p.get("name","")+p.get("cmd","")).lower()
                     for k in ["lsass","procdump","mimikatz","ntdsutil","pwdump","wce"])]
            ev["RUNNING_PROCESSES"] = NL.join(
                f"  {p.get('name','?'):25}  pid={str(p.get('pid','?')):6}  "
                f"user={p.get('euser',p.get('uname','?'))}"
                for p in items[:30]) or "  none"
            if tools:
                ev["CREDENTIAL_TOOLS_RUNNING"] = NL.join(
                    f"  [!] {p.get('name','?')}  pid={p.get('pid','?')}  "
                    f"cmd={p.get('cmd','')[:60]}" for p in tools)
        except Exception as e:
            ev["RUNNING_PROCESSES"] = f"  unavailable: {e}"

    # FIM change / script drop / persistence -> syscheck
    if any(b in behaviors for b in ["fim_change","script_drop","persistence","exploit"]):
        try:
            print(f"  [server api] GET /syscheck/{aid} — file integrity changes")
            fim  = wget(f"/syscheck/{aid}",{"limit":50})
            items= fim.get("affected_items",[])
            SUSP = ["/tmp","/dev/shm","appdata","temp","system32","\\run","startup"]
            pri  = [i for i in items if any(s in i.get("file","").lower() for s in SUSP)]
            shown= (pri+(i for i in items if i not in pri))
            ev["FIM_CHANGES"] = NL.join(
                f"  {i.get('type','?'):10}  {i.get('file','?')}"
                f"  (size:{i.get('size','?')} mtime:{str(i.get('mtime','?'))[:10]}"
                f"  owner:{i.get('uname','?')})"
                for i in list(shown)[:15]) or "  none"
            if pri:
                ev["FIM_SUSPICIOUS"] = NL.join(
                    f"  [!] {i.get('type','?'):10}  {i.get('file','?')}" for i in pri[:8])
        except Exception:
            fb = ix_search({"bool":{"must":[
                {"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}},
                {"bool":{"should":[{"match":{"rule.groups":"syscheck"}},
                                    {"match":{"rule.groups":"fim"}}]}}]}},
                size=15, sort=[{"timestamp":{"order":"desc"}}])
            ev["FIM_INDEX_ALERTS"] = NL.join(
                f"  {h.get('timestamp','')[:19]}  "
                f"{h.get('rule',{}).get('description','')[:55]}  "
                f"file={h.get('syscheck',{}).get('path','?')}"
                for h in fb["hits"][:10]) or "  none"

    # PowerShell -> targeted process search
    if "powershell" in behaviors and "RUNNING_PROCESSES" not in ev:
        try:
            print(f"  [server api] GET /syscollector/{aid}/processes — looking for active PowerShell")
            procs = wget(f"/syscollector/{aid}/processes",{"limit":50})
            ps    = [p for p in procs.get("affected_items",[])
                     if "powershell" in p.get("name","").lower()]
            ev["POWERSHELL_PROCESSES"] = NL.join(
                f"  {p.get('name','?')}  pid={p.get('pid','?')}  "
                f"user={p.get('euser','?')}  cmd={p.get('cmd','')[:80]}"
                for p in ps) or "  none active"
        except Exception as e:
            ev["POWERSHELL_PROCESSES"] = f"  unavailable: {e}"

    # Installed packages — relevant for exploit, persistence, defense_evasion
    # Helps the model identify vulnerable or suspicious software
    if any(b in behaviors for b in ["exploit", "persistence", "defense_evasion",
                                     "script_drop", "process_injection"]):
        try:
            print(f"  [server api] GET /syscollector/{aid}/packages — installed software inventory")
            pkgs = wget(f"/syscollector/{aid}/packages", {"limit": 100})
            items = pkgs.get("affected_items", [])
            if items:
                # Flag packages that are commonly abused or indicate risk
                SUSPECT = ["python", "perl", "ruby", "php", "nmap", "netcat", "nc",
                           "mimikatz", "metasploit", "sqlmap", "hydra", "john",
                           "wireshark", "tcpdump", "putty", "winscp", "psexec",
                           "sysinternals", "powersploit", "invoke-", "cobalt"]
                flagged = []
                all_pkgs = []
                for p in items:
                    name    = p.get("name", "")
                    version = p.get("version", "")
                    vendor  = p.get("vendor", "")
                    all_pkgs.append(f"{name} {version}".strip())
                    if any(s in name.lower() for s in SUSPECT):
                        flagged.append(f"  [FLAGGED] {name} {version} ({vendor})")

                lines = []
                if flagged:
                    lines.append("Flagged packages (potentially suspicious):")
                    lines.extend(flagged)
                # Show total count and a sample of recent/notable packages
                lines.append(f"Total installed: {len(items)} packages")
                # Show last 10 (often most recently installed)
                lines.append("Recently indexed (sample):")
                for p in items[-10:]:
                    lines.append(f"  {p.get('name','')} {p.get('version','')} — {p.get('vendor','unknown vendor')}")
                ev["INSTALLED_PACKAGES"] = "\n".join(lines)
            else:
                ev["INSTALLED_PACKAGES"] = "  no package data available (agent may be offline)"
        except Exception as e:
            ev["INSTALLED_PACKAGES"] = f"  unavailable: {e}"

    return ev

# -- Windows helpers -----------------------------------------------------------
def _is_windows(aid):
    try:
        d = wget(f"/agents/{aid}")
        if d.get("_404") or d.get("_400"): return None
        items = d.get("affected_items",[d])
        return "windows" in items[0].get("os",{}).get("name","").lower() if items else None
    except Exception:
        return None

def _sysmon_q(aid, since, groups=None, size=40):
    must = [{"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}}]
    if groups:
        must.append({"bool":{"should":[{"match":{"rule.groups":g}} for g in groups]}})
    return ix_search({"bool":{"must":must}}, size=size,
                     sort=[{"timestamp":{"order":"asc"}}])

# -- Evidence collection (chain-driven) ----------------------------------------
def collect(alert, since, chain=None):
    aid    = alert["agent_id"] or "000"
    is_win = _is_windows(aid)
    all_ev = (chain.get("all_events",[]) if chain else [])
    beh    = detect_behaviors(all_ev)

    # Stale/unknown agent -- indexer only
    if is_win is None:
        sysmon = _sysmon_q(aid, since,
            groups=["sysmon","windows","impacket",
                    "sysmon_eid10_detections","sysmon_eid11_detections"], size=30)
        recent = ix_search({"bool":{"must":[{"term":{"agent.id":aid}},
                                             {"range":{"timestamp":{"gte":since}}}]}},
                           size=15, sort=[{"timestamp":{"order":"desc"}}])
        return {"agent_status":   "NOT IN WAZUH ENROLLMENT -- indexer only",
                "behaviors_raw":  beh,
                "BEHAVIORS":      fmt_behaviors(beh),
                "SYSMON_EVENTS":  _fmt_sysmon(sysmon["hits"]),
                "RECENT_ALERTS":  NL.join(
                    f"  {h.get('timestamp','')[:19]}  "
                    f"[{h.get('rule',{}).get('level',0)}] "
                    f"{h.get('rule',{}).get('description','')[:65]}"
                    for h in recent["hits"][:10]) or "  none"}

    ev = {"agent_os":"Windows" if is_win else "Linux", "BEHAVIORS":fmt_behaviors(beh),
           "behaviors_raw": beh}

    # Windows: always get Sysmon events
    if is_win:
        print(f"  [indexer] Querying Sysmon/Windows events for agent {aid}...")
        sysmon = _sysmon_q(aid, since,
            groups=["sysmon","windows","impacket","sysmon_eid7_detections",
                    "sysmon_eid10_detections","sysmon_eid11_detections"], size=30)
        print(f"  [indexer] Found {sysmon['total']} Sysmon events")
        ev["SYSMON_EVENTS"] = _fmt_sysmon(sysmon["hits"])
        ev["sysmon_total"]  = sysmon["total"]

    # Chain-driven enrichment (same for Windows and Linux)
    ev.update(select_enrichment(beh, aid, since))
    return ev

def _fmt_ev(ev):
    return NL.join(f"{k}:\n{v}" if k==k.upper() and isinstance(v,str)
                   else f"  {k}: {v}" for k,v in ev.items())

def _fmt_chain(evts):
    lines = []
    for e in evts:
        line = f"    {e['ts']}  [{e['level']}] {e['rule'][:60]}"
        if e.get("src_ip"):  line += f"  src={e['src_ip']}"
        if e.get("cmd"):     line += f"\n      cmd    : {e['cmd']}"
        if e.get("image"):   line += f"\n      process: {e['image']}"
        if e.get("parent"):  line += f"\n      parent : {e['parent']}"
        if e.get("target"):  line += f"\n      file   : {e['target']}"
        if e.get("regkey"):  line += f"\n      regkey : {e['regkey']}"
        if e.get("user"):    line += f"\n      user   : {e['user']}"
        if not any(e.get(k) for k in ("cmd","image","target","regkey")) and e.get("log"):
            line += f"\n      log    : {e['log']}"
        lines.append(line)
    return NL.join(lines) or "    (none)"

# -- System prompt -------------------------------------------------------------
SYSTEM_PROMPT = """You are a SOC analyst. Write a short security report using only the evidence provided.

Rules:
- Plain text only. No markdown. No bold. No tables.
- Use dashes for bullets.
- Name exact processes, file paths, timestamps from the evidence.
- For MITRE: use tactic names only (Execution, Persistence, etc). Do not write T#### IDs.
- Stop writing after NEXT STEPS.

Format:

WHAT HAPPENED
- [timestamp] [process] [exact action]
- [timestamp] [process] [exact action]
- [timestamp] [process] [exact action]

ATTACK CHAIN
- Delivery: [how attacker got in]
- Execution: [exact command or process used]
- Impact: [persistence / credential access / lateral movement / evasion]

MITRE ATT&CK
- Primary tactic: [tactic name] - [technique description]
- Secondary tactic: [tactic name] - [technique description]

NEXT STEPS
Immediate:
- [specific containment action]
- [specific evidence to preserve]
Investigate:
- [exact file, registry key, or log]
- [specific question from the evidence]
"""


# -- LLM call -----------------------------------------------------------------
# MITRE ATT&CK tactics — stable, only 14 of them, never change
# Used to validate that the model uses tactic names not invented technique IDs.
MITRE_TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
    "Reconnaissance", "Resource Development"
}

import re as _re

def _validate_report(report, behaviors):
    """
    Lightweight post-generation check. No model call — pure Python.
    Only checks structural completeness and risk calibration.
    MITRE validation removed — tactic names are enforced via system prompt,
    not a curated ID list that requires constant maintenance.
    """
    problems = []
    report_upper = report.upper()

    # Required sections present
    for section in ["WHAT HAPPENED", "RISK", "NEXT STEPS"]:
        if section not in report_upper:
            problems.append(f"Missing section: {section}")

    # CRITICAL risk without HIGH-confidence Python-detected behavior
    if "CRITICAL" in report_upper:
        has_high = any(
            b.get("confidence") == "high"
            for b in behaviors.values()
        ) if behaviors else False
        if not has_high:
            problems.append("CRITICAL risk with no HIGH-confidence behaviors detected")

    return problems


def call_llm(alert, evidence, chain):
    """Single model call with thinking disabled for speed."""
    import threading, re as _reval

    chain_str = ""
    if chain and chain.get("total", 0) > 0:
        pats = "; ".join(chain["patterns"]) if chain["patterns"] else "none"
        chain_str = (
            f"\nATTACK CHAIN ({chain['total']} events +-30min):\n"
            f"  Patterns : {pats}\n"
            f"  Src IPs  : {', '.join(chain['src_ips']) or 'none'}\n"
            f"  BEFORE:\n{_fmt_chain(chain['before'][-3:])}\n"
            f"  AFTER:\n{_fmt_chain(chain['after'][:3])}\n"
        )

    # Cap evidence at 6000 chars to stay within context window.
    # Python-assembled header is not sent to the model — only the body prompt.
    ev_str    = _fmt_ev(evidence)
    if len(ev_str) > 6000:
        ev_str = ev_str[:6000] + "\n[evidence truncated for context limit]"

    prompt = (
        f"Alert  : [{alert['level']}] {alert['rule']}\n"
        f"Agent  : {', '.join(alert['agents'])} (ID: {alert['agent_id']})\n"
        f"Time   : {alert['ts']}\n"
        f"Src IP : {alert['src_ip'] or 'none'} | User: {alert['src_user'] or 'none'}\n"
        f"Log    : {alert['log']}\n"
        f"MITRE  : {alert['tactics']}\n\n"
        f"EVIDENCE:\n{ev_str}\n{chain_str}"
    )
    log.debug("Prompt length: %d chars", len(prompt))

    client = ollama.Client(host=C["OL_HOST"])
    t0     = time.perf_counter()

    # Ticker
    done = threading.Event()
    def _ticker():
        chars = ["|", "/", "-", "\\"]
        i = 0
        while not done.is_set():
            elapsed = int(time.perf_counter() - t0)
            sys.stdout.write(f"\r  Analysing... {chars[i%4]} {elapsed}s")
            sys.stdout.flush()
            i += 1
            time.sleep(0.5)
    threading.Thread(target=_ticker, daemon=True).start()

    result = ""
    in_think = False
    try:
        for chunk in client.chat(
            model=C["MODEL"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            stream=True,
            options={
                "temperature": 0,
                "num_ctx":     8192,
                "num_predict": 2000,   # thinking tokens + report body both fit
            }
        ):
            if STOP_FLAG.is_set():
                done.set()
                break
            text = chunk.message.content
            if not text:
                continue
            result += text
            # Track <think> block — suppress from display and result
            if "<think>" in result and not in_think:
                in_think = True
            if in_think:
                if "</think>" in result:
                    import re as _rt
                    result = _rt.sub(r"<think>.*?</think>", "", result,
                                     flags=_rt.DOTALL).strip()
                    # Also strip any leading garbage before </think>
                    result = _rt.sub(r"^.*?</think>", "", result,
                                     flags=_rt.DOTALL).strip()
                    in_think = False
                    if result and not done.is_set():
                        done.set()
                        sys.stdout.write("\r" + " " * 60 + "\r")
                        elapsed = int(time.perf_counter() - t0)
                        sys.stdout.write(f"  Generating ({elapsed}s thinking)...\n\n")
                        sys.stdout.flush()
                        print(result, end="", flush=True)
                continue  # still in think block, don't print
            # Normal output token
            if result and not done.is_set():
                done.set()
                sys.stdout.write("\r" + " " * 60 + "\r")
                elapsed = int(time.perf_counter() - t0)
                sys.stdout.write(f"  Generating ({elapsed}s thinking)...\n\n")
                sys.stdout.flush()
            print(text, end="", flush=True)
        print()
    except Exception as e:
        done.set()
        err = str(e)
        print(f"\n  ERR {err}")
        if "not found" in err.lower(): print(f"     -> Run: ollama pull {C['MODEL']}")
        elif "connection" in err.lower(): print("     -> Run: ollama serve")
        result = f"[unavailable -- {err}]"
    finally:
        done.set()

    elapsed = int(time.perf_counter() - t0)
    log.info("Ollama -> %ds | %d chars", elapsed, len(result))

    # Strip thinking tokens
    import re as _rethink
    # Final cleanup of any remaining think artifacts
    import re as _rethink
    result = _rethink.sub(r"<think>.*?</think>", "", result, flags=_rethink.DOTALL)
    result = _rethink.sub(r"^.*?</think>", "", result, flags=_rethink.DOTALL)
    result = result.strip()

    # Python builds the header — not the model
    behaviors = evidence.get("behaviors_raw", {})
    high_conf = [k for k, v in behaviors.items() if v.get("confidence") == "high"]
    med_conf  = [k for k, v in behaviors.items() if v.get("confidence") == "medium"]
    critical  = {"credential_dump","lateral_smb","wmi_execution",
                 "pass_the_hash","process_injection","exploit"}
    if any(b in critical for b in high_conf) or len(high_conf) >= 2:
        risk = "CRITICAL"
    elif high_conf or len(med_conf) >= 2:
        risk = "HIGH"
    elif med_conf:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    status = "Disconnected" if "NOT IN WAZUH" in evidence.get("agent_status","")              else "Active"
    os_    = evidence.get("agent_os", "Unknown")

    beh_str = ""
    if behaviors:
        beh_str = "\nDETECTED BEHAVIORS\n" + "\n".join(
            f"- {k.replace('_',' ').title()} [{v['confidence'].upper()}]"
            for k, v in behaviors.items()
        ) + "\n"

    report = (
        f"AGENT   : {', '.join(alert['agents'])} (ID: {alert['agent_id']}) | {os_}\n"
        f"TIME    : {alert['ts']}\n"
        f"STATUS  : {status}\n"
        f"RISK    : {risk}\n"
        f"{beh_str}\n"
        f"{result}\n"
    )

    # No MITRE ID validation — system prompt instructs tactic names only

    print("\n" + report)
    log.info("Report done: %d chars, risk=%s", len(report), risk)
    return report



# ── Inventory (syscollector snapshot) ─────────────────────────────────────────
# Read-only host inventory queries — no LLM, fast, factual.
# Optionally flags suspicious findings (odd ports, hacking tools).

_SUSPECT_PORTS = {4444:"Metasploit default", 1337:"common backdoor",
                  31337:"Back Orifice", 12345:"NetBus", 5555:"ADB/remote",
                  6666:"IRC botnet", 6667:"IRC botnet", 8080:"proxy/alt-http"}

# Suspect tool names. Matched as whole words (regex \b boundaries) so that
# legitimate processes like "mDNSResponder" don't false-positive on "responder".
_SUSPECT_PKG = ["nmap","netcat","ncat","mimikatz","metasploit","sqlmap",
                "hydra","wireshark","tcpdump","psexec",
                "powersploit","cobaltstrike","bloodhound","impacket",
                "sharphound","rubeus","kerbrute","crackmapexec","secretsdump",
                "winpeas","linpeas","seatbelt","certify"]

import re as _re_susp
# Pre-compile word-boundary patterns. "responder" alone is too broad
# (matches mDNSResponder) so it is intentionally excluded — use a more
# specific indicator if hunting for the Responder tool.
_SUSPECT_RE = _re_susp.compile(
    r"\b(" + "|".join(_re_susp.escape(s) for s in _SUSPECT_PKG) + r")\b",
    _re_susp.IGNORECASE)

def _is_suspect(text):
    """Whole-word match against the suspect tool list."""
    return bool(_SUSPECT_RE.search(text or ""))

def inventory(kind, agent_id, only_suspicious=False):
    """
    kind: "packages" | "ports" | "processes" | "files"
    only_suspicious: if True, return ONLY flagged/suspicious items.
    Returns a structured dict with the raw data and any flagged items.
    """
    if not agent_id:
        return {"error": "Inventory queries require an agent ID"}

    aid = agent_id.zfill(3)

    try:
        if kind == "ports":
            r     = wget(f"/syscollector/{aid}/ports", {"limit": 200})
            items = r.get("affected_items", [])
            rows, flags = [], []
            for p in items:
                port  = p.get("local", {}).get("port")
                proto = p.get("protocol", "")
                state = p.get("state", "")
                proc  = p.get("process", "?")
                sus   = port in _SUSPECT_PORTS
                rows.append({"port": port, "protocol": proto,
                             "state": state, "process": proc, "_sus": sus})
                if sus:
                    flags.append(f"Port {port} ({_SUSPECT_PORTS[port]}) — {proc}")
            if only_suspicious:
                rows = [r for r in rows if r.get("_sus")]
            return {"kind": "ports", "agent": aid, "count": len(rows),
                    "rows": rows, "flags": flags,
                    "only_suspicious": only_suspicious}

        elif kind == "processes":
            r     = wget(f"/syscollector/{aid}/processes", {"limit": 300})
            items = r.get("affected_items", [])
            rows, flags = [], []
            for p in items:
                name = p.get("name", "")
                pid  = p.get("pid", "")
                ppid = p.get("ppid", "")
                cmd  = p.get("cmd", "") or p.get("command", "")
                low  = (name + " " + cmd).lower()
                sus  = _is_suspect(low)
                rows.append({"name": name, "pid": pid, "ppid": ppid,
                             "cmd": cmd[:120], "_sus": sus})
                if sus:
                    flags.append(f"{name} (PID {pid}) — {cmd[:80]}")
            if only_suspicious:
                rows = [r for r in rows if r.get("_sus")]
            else:
                rows = rows[:100]
            return {"kind": "processes", "agent": aid, "count": len(rows),
                    "rows": rows, "flags": flags,
                    "only_suspicious": only_suspicious}

        elif kind == "packages":
            r     = wget(f"/syscollector/{aid}/packages", {"limit": 500})
            items = r.get("affected_items", [])
            rows, flags = [], []
            for p in items:
                name    = p.get("name", "")
                version = p.get("version", "")
                vendor  = p.get("vendor", "")
                sus     = _is_suspect(name)
                rows.append({"name": name, "version": version,
                             "vendor": vendor, "_sus": sus})
                if sus:
                    flags.append(f"{name} {version} ({vendor})")
            if only_suspicious:
                rows = [r for r in rows if r.get("_sus")]
            return {"kind": "packages", "agent": aid, "count": len(rows),
                    "rows": rows, "flags": flags,
                    "only_suspicious": only_suspicious}

        elif kind == "files":
            r     = wget(f"/syscheck/{aid}", {"limit": 200})
            items = r.get("affected_items", [])
            rows, flags = [], []
            SUSP_PATH = ["/tmp", "/dev/shm", "appdata", "\\temp",
                         "system32", "\\run", "startup"]
            for f in items:
                path  = f.get("file", "")
                mtime = f.get("mtime", "") or f.get("date", "")
                sha   = f.get("sha256", "") or f.get("sha1", "")
                sus   = any(s in path.lower() for s in SUSP_PATH)
                rows.append({"file": path, "mtime": str(mtime)[:19],
                             "hash": sha[:16], "_sus": sus})
                if sus:
                    flags.append(f"{path}  (modified {str(mtime)[:19]})")
            if only_suspicious:
                rows = [r for r in rows if r.get("_sus")]
            else:
                rows = rows[:100]
            return {"kind": "files", "agent": aid, "count": len(rows),
                    "rows": rows, "flags": flags,
                    "only_suspicious": only_suspicious}

        else:
            return {"error": f"Unknown inventory kind: {kind}"}

    except Exception as e:
        return {"error": str(e), "kind": kind, "agent": aid}


# ── Threat Hunt ───────────────────────────────────────────────────────────────

# Known IOC patterns
import re as _re_hunt
_IP_RE   = _re_hunt.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = _re_hunt.compile(r"^[0-9a-fA-F]{32,64}$")
_CVE_RE  = _re_hunt.compile(r"CVE-\d{4}-\d+", _re_hunt.IGNORECASE)

# TTP keyword → OpenSearch field mapping
TTP_MAP = {
    # Pass-the-hash / credential access
    "pass the hash":       [{"wildcard":{"rule.description":{"value":"*pass-the-hash*","case_insensitive":True}}},
                            {"match":{"rule.groups":"authentication_failed"}}],
    "pth":                 [{"wildcard":{"rule.description":{"value":"*pass-the-hash*","case_insensitive":True}}}],
    "credential dump":     [{"wildcard":{"rule.description":{"value":"*credential*","case_insensitive":True}}},
                            {"wildcard":{"data.win.eventdata.image":{"value":"*lsass*","case_insensitive":True}}}],
    "mimikatz":            [{"wildcard":{"data.win.eventdata.image":{"value":"*mimikatz*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*mimikatz*","case_insensitive":True}}}],
    # Lateral movement
    "lateral movement":    [{"match":{"rule.groups":"impacket"}},
                            {"wildcard":{"rule.description":{"value":"*lateral*","case_insensitive":True}}}],
    "psexec":              [{"wildcard":{"data.win.eventdata.image":{"value":"*psexec*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*psexec*","case_insensitive":True}}}],
    "wmi":                 [{"wildcard":{"data.win.eventdata.image":{"value":"*wmiprvse*","case_insensitive":True}}},
                            {"match":{"rule.groups":"impacket"}}],
    # Persistence
    "scheduled task":      [{"wildcard":{"rule.description":{"value":"*scheduled task*","case_insensitive":True}}},
                            {"match":{"data.win.system.eventID":"4698"}}],
    "registry persistence":[{"wildcard":{"rule.description":{"value":"*registry*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*persistence*","case_insensitive":True}}}],
    "new service":         [{"match":{"data.win.system.eventID":"4697"}},
                            {"wildcard":{"rule.description":{"value":"*new service*","case_insensitive":True}}}],
    # Defense evasion
    "process injection":   [{"wildcard":{"rule.description":{"value":"*process injection*","case_insensitive":True}}},
                            {"match":{"rule.groups":"sysmon_eid10_detections"}}],
    "powershell":          [{"wildcard":{"data.win.eventdata.image":{"value":"*powershell*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*powershell*","case_insensitive":True}}}],
    # Discovery
    "port scan":           [{"wildcard":{"rule.description":{"value":"*port scan*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*nmap*","case_insensitive":True}}}],
    "reconnaissance":      [{"wildcard":{"rule.description":{"value":"*recon*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*enumeration*","case_insensitive":True}}}],
    # Execution
    "script drop":         [{"wildcard":{"rule.description":{"value":"*script*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*dropped*","case_insensitive":True}}}],
    "malware":             [{"wildcard":{"rule.description":{"value":"*malware*","case_insensitive":True}}},
                            {"wildcard":{"rule.description":{"value":"*trojan*","case_insensitive":True}}}],
}

def _hunt_ioc(value, days, agent_id=None):
    """Search for an IP, hash, domain, or CVE.
    Uses wildcard (case-insensitive) since description/full_log are keyword fields."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    must  = [{"range":{"timestamp":{"gte":since}}}]
    if agent_id:
        must.append({"term":{"agent.id": agent_id}})

    if _IP_RE.match(value):    hunt_type = "IP Address"
    elif _HASH_RE.match(value): hunt_type = "File Hash"
    elif _CVE_RE.match(value):  hunt_type = "CVE"
    else:                       hunt_type = "Indicator"

    v = value.lower()
    should = [
        {"wildcard": {"full_log":         {"value": f"*{v}*", "case_insensitive": True}}},
        {"wildcard": {"rule.description": {"value": f"*{v}*", "case_insensitive": True}}},
        {"match":    {"data.srcip": value}},
        {"match":    {"data.dstip": value}},
    ]
    q = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}

    log.info("HUNT IOC value=%r type=%s days=%d", value, hunt_type, days)

    aggs = {
        "by_agent": {"terms": {"field": "agent.id", "size": 20},
                     "aggs":  {"name":  {"terms": {"field": "agent.name", "size": 1}},
                               "first": {"min":   {"field": "timestamp"}},
                               "last":  {"max":   {"field": "timestamp"}}}},
        "total":    {"value_count": {"field": "rule.level"}},
    }
    agg_result = ix_agg(q, aggs)
    hits       = ix_search(q, size=10, sort=[{"timestamp": {"order": "desc"}}])
    total = agg_result.get("total", {}).get("value", 0)
    log.info("HUNT IOC result: total=%d", total)

    return {
        "hunt_type": hunt_type,
        "value":     value,
        "days":      days,
        "total":     total,
        "by_agent":  agg_result.get("by_agent", {}).get("buckets", []),
        "samples":   hits.get("hits", []),
    }


def _hunt_ttp(query, days, agent_id=None):
    """Search for a TTP by keyword.
    NOTE: rule.description is a KEYWORD field in this index, so `match`
    does not work — only `wildcard` (lowercase) matches. Confirmed via diagnostics.
    """
    since  = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    must   = [{"range": {"timestamp": {"gte": since}}}]
    if agent_id:
        must.append({"term": {"agent.id": agent_id}})

    q_lower  = query.lower().strip()
    ttp_name = query

    # rule.description is a KEYWORD field, so we use case_insensitive wildcard.
    # For multi-word queries, match each word independently (AND) so word order
    # and filler words between them do not break the match.
    # "cis benchmark" matches "CIS Benchmark for Amazon Linux..." correctly.
    words = [w for w in q_lower.split() if len(w) > 1]

    if len(words) > 1:
        # Each word must appear somewhere in the description (AND of wildcards)
        desc_must = [{"wildcard": {"rule.description":
                      {"value": f"*{w}*", "case_insensitive": True}}} for w in words]
        log_must  = [{"wildcard": {"full_log":
                      {"value": f"*{w}*", "case_insensitive": True}}} for w in words]
        should = [
            {"bool": {"must": desc_must}},   # all words in description
            {"bool": {"must": log_must}},    # all words in full_log
            {"match": {"rule.groups": q_lower}},
        ]
    else:
        # Single word — simple wildcard
        should = [
            {"wildcard": {"rule.description": {"value": f"*{q_lower}*",
                                               "case_insensitive": True}}},
            {"wildcard": {"full_log":         {"value": f"*{q_lower}*",
                                               "case_insensitive": True}}},
            {"match":    {"rule.groups": q_lower}},
        ]

    # Add known-TTP specific group/field clauses if mapped
    for key, clauses in TTP_MAP.items():
        if key in q_lower or q_lower in key:
            should.extend(clauses)
            ttp_name = key
            break

    q = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}

    log.info("HUNT TTP query=%r days=%d agent=%s", query, days, agent_id)

    aggs = {
        "by_agent": {"terms": {"field": "agent.id", "size": 20},
                     "aggs":  {"name": {"terms": {"field": "agent.name", "size": 1}}}},
        "by_rule":  {"terms": {"field": "rule.description", "size": 10}},
        "total":    {"value_count": {"field": "rule.level"}},
        "severity": {"max":         {"field": "rule.level"}},
    }
    agg_result = ix_agg(q, aggs)

    hits  = ix_search(q, size=10, sort=[{"timestamp": {"order": "desc"}}])
    total = agg_result.get("total", {}).get("value", 0)
    log.info("HUNT TTP result: total=%d", total)

    return {
        "hunt_type": "TTP",
        "ttp_name":  ttp_name,
        "value":     query,
        "days":      days,
        "total":     total,
        "max_sev":   agg_result.get("severity", {}).get("value", 0),
        "by_agent":  agg_result.get("by_agent", {}).get("buckets", []),
        "by_rule":   agg_result.get("by_rule",  {}).get("buckets", []),
        "by_tactic": [],
        "samples":   hits.get("hits", []),
    }




# ── Alert Triage ──────────────────────────────────────────────────────────────
# Scores and buckets all alerts by URGENCY using signals derived from the
# data itself — NOT a hardcoded scenario catalog. Adapts to any environment.
#
# Score = severity + behavior-confidence + chain-density + mitre-presence
#         - noise-penalty (how common this rule is in the baseline window)
#
# Weights are configurable via .env so analysts can tune per environment.

TRIAGE_WEIGHTS = {
    "severity":  float(os.getenv("TRIAGE_W_SEVERITY",  "1.0")),
    "behavior":  float(os.getenv("TRIAGE_W_BEHAVIOR",  "4.0")),
    "chain":     float(os.getenv("TRIAGE_W_CHAIN",     "0.5")),
    "mitre":     float(os.getenv("TRIAGE_W_MITRE",     "2.0")),
    "noise":     float(os.getenv("TRIAGE_W_NOISE",     "3.0")),
}

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


# High-risk tactics that warrant immediate attention when present
_HIGH_RISK_TACTICS = {"Privilege Escalation", "Credential Access",
                      "Lateral Movement", "Exfiltration", "Command and Control",
                      "Defense Evasion", "Impact"}

def _triage_insight(grp, count, max_lv, tactics, daily_rate, top_rules):
    """
    Derive a human-readable WHY and WHAT-TO-LOOK-AT from data signals only.
    No hardcoded scenario catalog — text is composed from the signal pattern.
    Returns (reason, action, focus).
    """
    high_risk = [t for t in tactics if t in _HIGH_RISK_TACTICS]
    is_common = daily_rate > 50
    is_rare   = daily_rate < 1 and count >= 3   # rare but clustered

    # ── WHY does this need a look (reason) ───────────────────────────────────
    parts = []
    if max_lv >= 12:
        parts.append(f"high-severity (level {max_lv})")
    elif max_lv >= 7:
        parts.append(f"medium-severity (level {max_lv})")
    else:
        parts.append(f"low-severity (level {max_lv})")

    if high_risk:
        parts.append(f"tagged with {', '.join(high_risk)}")
    if count >= 15:
        parts.append(f"high volume ({count} events — a sustained burst, not a one-off)")
    elif count >= 5:
        parts.append(f"{count} related events")

    if is_rare:
        parts.append("rarely seen in your environment (anomalous)")
    elif is_common:
        parts.append(f"very common (~{int(daily_rate)}/day — usually routine)")

    reason = "; ".join(parts).capitalize() + "."

    # ── WHAT to look at (focus) — derived from tactic + rule signals ─────────
    focus = []
    rule_txt = " ".join(top_rules).lower()

    if "Privilege Escalation" in tactics or "Persistence" in tactics:
        if "service" in rule_txt:
            focus.append("the new service's ImagePath and whether it was authorized")
        if "scheduled task" in rule_txt or "taskschd" in rule_txt:
            focus.append("the scheduled task definition and what it executes")
        if "registry" in rule_txt:
            focus.append("the registry key modified and its value")
    if "Credential Access" in tactics:
        focus.append("which account was targeted and the source process")
    if "Lateral Movement" in tactics:
        focus.append("the source and destination hosts, and the account used")
    if "Command and Control" in tactics or "Execution" in tactics:
        if "script" in rule_txt or "powershell" in rule_txt:
            focus.append("the script content and where it was dropped")
        if "cmd" in rule_txt or "command" in rule_txt:
            focus.append("the exact command line executed")
    if "Defense Evasion" in tactics:
        if "disconnect" in rule_txt:
            focus.append("why the agent disconnected — possible tampering")
        if "delete" in rule_txt or "cleared" in rule_txt:
            focus.append("what was deleted and by which process")
    if not focus:
        focus.append("the event timeline and the process that triggered it")

    # ── WHAT to do (action) ──────────────────────────────────────────────────
    if max_lv >= 12 and high_risk:
        action = "Investigate this agent now — run a full investigation."
    elif high_risk and count >= 10:
        action = "Run an investigation on this agent to see the full attack chain."
    elif is_common and max_lv < 7:
        action = "Likely routine. Dismiss unless it correlates with a higher-priority situation."
    elif is_rare:
        action = "Unusual pattern — worth a closer look even at low severity."
    else:
        action = "Review the sample events; investigate if the context looks unexpected."

    return reason, action, focus

def triage(hours=24, agent_id=None, min_sev=3):
    """
    Triage all alerts in the window. Returns prioritized situation buckets.
    No hardcoded scenarios — scoring is derived from live data signals.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # 1. Pull aggregated alert groups (reuses the same aggregation as fetch_alerts)
    must = [{"range":{"timestamp":{"gte":since}}},
            {"range":{"rule.level":{"gte":min_sev}}}]
    if agent_id:
        must.append({"term":{"agent.id":agent_id}})
    q = {"bool":{"must":must}}

    agg = ix_agg(q, {
        "total":    {"value_count":{"field":"rule.level"}},
        "by_group": {"terms":{"field":"rule.groups","size":50,
                              "order":{"max_lv":"desc"}},
                     "aggs":{"max_lv":   {"max":{"field":"rule.level"}},
                             "count":    {"value_count":{"field":"rule.level"}},
                             "agents":   {"terms":{"field":"agent.name","size":5}},
                             "tactics":  {"terms":{"field":"rule.mitre.tactic","size":5}},
                             "top_rules":{"terms":{"field":"rule.description","size":3}},
                             "sample":   {"top_hits":{"size":1,
                                          "sort":[{"rule.level":{"order":"desc"}}],
                                          "_source":["timestamp","agent.name",
                                          "rule.description","rule.level"]}}}},
    })

    total_alerts = agg.get("total",{}).get("value",0)
    groups       = agg.get("by_group",{}).get("buckets",[])

    if total_alerts == 0:
        return {"mode":"triage","hours":hours,"total":0,"situations":[],
                "urgent":[], "review":[], "routine":[]}

    W = TRIAGE_WEIGHTS
    situations = []

    for g in groups:
        grp_name = g["key"]
        count    = g["count"]["value"]
        max_lv   = g["max_lv"]["value"] or 0
        agents   = [b["key"] for b in g.get("agents",{}).get("buckets",[])]
        tactics  = [b["key"] for b in g.get("tactics",{}).get("buckets",[])]
        rules    = [b["key"] for b in g.get("top_rules",{}).get("buckets",[])]
        sample_h = g.get("sample",{}).get("hits",{}).get("hits",[])
        sample   = sample_h[0]["_source"] if sample_h else {}

        # ── Score from data-derived signals ──────────────────────────────────
        # Severity: normalized 0-1 (Wazuh levels go to ~15)
        sev_score = (max_lv / 15.0) * W["severity"]

        # MITRE presence: does the data label this with a tactic?
        mitre_score = (W["mitre"] if tactics else 0.0)

        # Chain density: more events in the group = denser situation (log scale)
        import math as _m
        chain_score = _m.log10(count + 1) * W["chain"]

        # Rarity / noise: how common is this rule group in the baseline?
        # Common rules (high daily rate) get penalized.
        daily_rate  = _rule_baseline_freq(grp_name)
        # Normalize: >100/day = very noisy, demote heavily
        noise_penalty = min(daily_rate / 100.0, 1.0) * W["noise"]

        # Behavior confidence would require pulling the chain per group —
        # expensive. We approximate using severity + tactic presence here,
        # and the analyst can Investigate any group for full behavior detection.

        score = sev_score + mitre_score + chain_score - noise_penalty

        reason, action, focus = _triage_insight(
            grp_name, count, max_lv, tactics, daily_rate, rules)

        situations.append({
            "group":       grp_name,
            "count":       count,
            "max_level":   max_lv,
            "agents":      agents,
            "tactics":     tactics,
            "top_rules":   rules,
            "sample":      sample,
            "daily_rate":  round(daily_rate, 1),
            "score":       round(score, 2),
            "reason":      reason,
            "action":      action,
            "focus":       focus,
        })

    # Sort by score, highest first
    situations.sort(key=lambda s: s["score"], reverse=True)

    # ── Bucket by score thresholds (relative + absolute) ─────────────────────
    # Absolute floors based on severity ensure a true crit is always urgent
    urgent, review, routine = [], [], []
    for s in situations:
        if s["max_level"] >= 12 and s["score"] > 0:
            urgent.append(s)
        elif s["score"] >= 1.0:
            review.append(s)
        else:
            routine.append(s)

    return {
        "mode":        "triage",
        "hours":       hours,
        "total":       total_alerts,
        "situations":  len(situations),
        "urgent":      urgent,
        "review":      review,
        "routine":     routine,
    }



def triage_insights_llm(situations):
    """
    Generator: takes Python-scored situations and streams an LLM analysis.
    ONE model call. The LLM writes a verdict + recommendation per situation.
    Yields text chunks (the raw model output) for SSE streaming.
    Python keeps the scoring/bucketing — the LLM only adds judgment.
    """
    if not situations:
        yield "No situations to analyse."
        return

    # Build a compact summary of each situation — NOT raw events.
    lines = []
    for i, s in enumerate(situations, 1):
        agents  = ", ".join(s.get("agents", [])[:3]) or "unknown"
        tactics = ", ".join(s.get("tactics", [])) or "none"
        rules   = "; ".join(s.get("top_rules", [])[:2])
        rate    = s.get("daily_rate", 0)
        lines.append(
            f"{i}. GROUP: {s['group']}\n"
            f"   Severity: {s['max_level']} | Events: {s['count']} | "
            f"Agents: {agents}\n"
            f"   MITRE tactics: {tactics}\n"
            f"   Rules: {rules}\n"
            f"   Baseline rate: {rate}/day "
            f"({'common/likely-noise' if rate > 50 else 'rare/notable' if rate < 1 else 'occasional'})"
        )
    situations_block = "\n\n".join(lines)

    system = (
        "You are a senior SOC analyst doing alert triage. You are given "
        "pre-grouped, pre-scored alert situations. For EACH situation, give a "
        "one-line verdict and a concrete recommendation. Be specific and brief. "
        "Plain text only, no markdown. Do NOT re-score or re-order — the priority "
        "is already decided. Focus on WHAT this likely is and WHAT the analyst "
        "should do. Use the exact format below for every situation."
    )
    user = (
        f"Here are {len(situations)} alert situations to triage:\n\n"
        f"{situations_block}\n\n"
        f"For each numbered situation, respond in exactly this format:\n"
        f"[n] VERDICT: <one line: likely benign / suspicious / needs investigation / "
        f"likely attack>\n"
        f"    WHY: <one line — what the evidence suggests>\n"
        f"    DO: <one line — the specific next action>\n"
    )

    client = ollama.Client(host=C["OL_HOST"])
    try:
        for chunk in client.chat(
            model=C["MODEL"],
            messages=[{"role": "system", "content": system},
                      {"role": "user",   "content": user}],
            stream=True,
            options={"temperature": 0, "num_ctx": 8192, "num_predict": 1500},
        ):
            if STOP_FLAG.is_set():
                break
            txt = chunk.message.content
            if txt:
                yield txt
    except Exception as e:
        yield f"\n[LLM analysis unavailable: {e}]"


# ── Threat Category Hunt ──────────────────────────────────────────────────────
# Maps high-level analyst questions to bundles of detection patterns.
# Each category searches rule.description (keyword field → wildcards) and
# rule.groups for indicators of that whole class of attack.

THREAT_CATEGORIES = {
    "exfiltration": {
        "label": "Data Exfiltration",
        "desc_terms": ["exfiltrat", "data transfer", "large outbound",
                       "dns tunnel", "upload", "compress", "archive created",
                       "rar", "7z", "zip", "ftp", "scp", "data staged"],
        "groups": ["sysmon_eid3_detections"],
        "tactics": ["Exfiltration", "Collection", "Command and Control"],
    },
    "rce": {
        "label": "Remote Code Execution",
        "desc_terms": ["remote command", "remote code", "remote execution",
                       "wmiprvse", "psexec", "services.exe", "powershell remot",
                       "winrm", "impacket", "suspicious cmd", "command execution"],
        "groups": ["impacket", "sysmon"],
        "tactics": ["Execution", "Lateral Movement"],
    },
    "privesc": {
        "label": "Privilege Escalation",
        "desc_terms": ["privilege escalation", "uac bypass", "token",
                       "elevated", "administrators group", "admin rights",
                       "se_debug", "getsystem", "potato", "exploit"],
        "groups": ["sysmon"],
        "tactics": ["Privilege Escalation"],
    },
    "persistence": {
        "label": "Persistence Mechanisms",
        "desc_terms": ["persistence", "scheduled task", "new service",
                       "registry run", "startup", "autorun", "wmi subscription",
                       "logon script", "service created"],
        "groups": [],
        "tactics": ["Persistence"],
    },
    "credential_access": {
        "label": "Credential Access",
        "desc_terms": ["credential", "lsass", "mimikatz", "pass-the-hash",
                       "ntlm", "kerberoast", "dcsync", "sam dump",
                       "password", "hash dump"],
        "groups": [],
        "tactics": ["Credential Access"],
    },
    "lateral": {
        "label": "Lateral Movement",
        "desc_terms": ["lateral", "remote logon", "smb", "psexec", "wmi",
                       "rdp", "pass-the-hash", "remote service", "admin share"],
        "groups": ["impacket"],
        "tactics": ["Lateral Movement"],
    },
    "defense_evasion": {
        "label": "Defense Evasion",
        "desc_terms": ["defense evasion", "cleared", "log deleted",
                       "disabled", "bypass", "obfuscat", "encoded",
                       "process injection", "masquerad", "timestomp"],
        "groups": [],
        "tactics": ["Defense Evasion"],
    },
    "critical": {
        "label": "Critical Alerts Requiring Attention",
        "desc_terms": [],   # severity-driven, not keyword
        "groups": [],
        "tactics": [],
        "min_level": 12,    # only high/critical
    },
}

def threat_hunt(category, hours=24, agent_id=None):
    """
    Hunt for a whole CATEGORY of threat (exfiltration, rce, privesc, etc).
    Returns a structured briefing: matches, affected agents, top rules,
    tactic spread, and sample events.
    """
    cat = THREAT_CATEGORIES.get(category)
    if not cat:
        return {"error": f"Unknown threat category: {category}"}

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    must  = [{"range": {"timestamp": {"gte": since}}}]
    if agent_id:
        must.append({"term": {"agent.id": agent_id}})

    # Minimum severity floor for the category (critical = 12+)
    min_level = cat.get("min_level", 0)
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})

    # Build should-clauses from description terms (wildcard) + groups (match)
    should = []
    for term in cat["desc_terms"]:
        should.append({"wildcard": {"rule.description":
                       {"value": f"*{term.lower()}*", "case_insensitive": True}}})
    for grp in cat["groups"]:
        should.append({"match": {"rule.groups": grp}})
    # Tactic match (if the field exists in the mapping)
    for tactic in cat["tactics"]:
        should.append({"match_phrase": {"rule.mitre.tactic": tactic}})

    if should:
        q = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}
    else:
        # Critical-only: no should clauses, just the severity floor
        q = {"bool": {"must": must}}

    log.info("THREAT HUNT category=%s hours=%d agent=%s", category, hours, agent_id)

    aggs = {
        "by_agent": {"terms": {"field": "agent.id", "size": 20},
                     "aggs":  {"name": {"terms": {"field": "agent.name", "size": 1}}}},
        "by_rule":  {"terms": {"field": "rule.description", "size": 12}},
        "by_level": {"terms": {"field": "rule.level", "size": 15}},
        "total":    {"value_count": {"field": "rule.level"}},
        "max_sev":  {"max":         {"field": "rule.level"}},
    }
    agg = ix_agg(q, aggs)
    hits = ix_search(q, size=15, sort=[{"rule.level": {"order": "desc"}},
                                       {"timestamp":  {"order": "desc"}}])
    total = agg.get("total", {}).get("value", 0)
    log.info("THREAT HUNT result: category=%s total=%d", category, total)

    return {
        "mode":       "threat_category",
        "category":   category,
        "label":      cat["label"],
        "hours":      hours,
        "total":      total,
        "max_sev":    agg.get("max_sev", {}).get("value", 0),
        "by_agent":   agg.get("by_agent", {}).get("buckets", []),
        "by_rule":    agg.get("by_rule",  {}).get("buckets", []),
        "by_level":   agg.get("by_level", {}).get("buckets", []),
        "tactics":    cat["tactics"],
        "samples":    hits.get("hits", []),
    }


def hunt(query, days=7, agent_id=None, hunt_type="auto"):
    """
    Main hunt entry point.
    hunt_type: "auto" (detect), "ioc" (force IOC), "ttp" (force TTP)
    Returns structured result dict.
    """
    query = query.strip()
    if not query:
        return {"error": "Empty query"}

    # Auto-detect type
    if hunt_type == "auto":
        if (_IP_RE.match(query) or _HASH_RE.match(query) or
                _CVE_RE.match(query) or "." in query and len(query) < 50):
            hunt_type = "ioc"
        else:
            hunt_type = "ttp"

    if hunt_type == "ioc":
        return _hunt_ioc(query, days, agent_id)
    else:
        return _hunt_ttp(query, days, agent_id)

# -- Main ---------------------------------------------------------------------
_enrolled = {}

# Stop flag — set by the UI to interrupt a running investigation
import threading as _threading
STOP_FLAG = _threading.Event()

def run(severity=MIN_SEV, hours=HOURS, agent_id=None):
    global _enrolled
    since = _since(hours)
    print(f"severity>={severity} | last {hours}h | "
          f"{'agent '+agent_id if agent_id else 'all agents'}\n")

    try:
        fleet = wget("/agents",{"limit":500,"select":"id,name,status"})
        _enrolled = {a["id"]:a.get("name","?") for a in fleet.get("affected_items",[])}
    except Exception as e:
        log.debug("Agent list unavailable: %s", e)

    print("  Fetching alerts...", end="", flush=True)
    try:
        total, dist, alerts = fetch_alerts(since, severity, agent_id)
    except RuntimeError as e:
        print(f"\n\n  ERR FATAL: {e}\n"); return
    except Exception as e:
        print(f"\n\n  ERR {type(e).__name__}: {e}\n"); return

    if not alerts: print("  No alerts found.\n"); return
    log.debug("Alerts: %d total, groups: %s", total, [a['group'] for a in alerts[:5]])

    # One slot per type, max 5
    seen, top = set(), []
    TYPES = {"fim":["syscheck","fim"],"auth":["authentication","windows_security"],
             "port":["network_changes","netstat"],"process":["sysmon","windows","impacket"]}
    def _type(g):
        for t,kws in TYPES.items():
            if any(k in g for k in kws): return t
        return "generic"
    for a in alerts:
        t = _type(a["group"])
        if t not in seen: seen.add(t); top.append(a)
        if len(top)>=5: break
    if not top: top = alerts[:3]

    # Chains -- one per agent
    chains = {}
    for aid in {a["agent_id"] or agent_id or "000" for a in top}:
        ts = next((a["ts"] for a in top if (a["agent_id"] or "000")==aid), None)
        if not ts: continue
        log.debug("Building attack chain for agent %s", aid)
        try:
            chains[aid] = get_chain(aid, ts)
            c = chains[aid]
            log.debug("Chain: %d events, patterns: %s", c['total'], c['patterns'])
        except Exception as e:
            print(f" ERR {e}"); chains[aid] = None

    log.debug("Analysing %d alert group(s)", len(top))
    for i,alert in enumerate(top,1):
        aid   = alert["agent_id"] or agent_id or "000"
        chain = chains.get(aid)
        log.debug("Collecting evidence for alert %d/%d", i, len(top))
        try:
            evidence = collect(alert, since, chain=chain)
            # Print the trigger alert as context before the report
            print(f"TRIGGER ALERT")
            print(f"- Rule    : [{alert['level']}] {alert['rule']}")
            print(f"- Agent   : {', '.join(alert['agents'])} (ID: {alert['agent_id']})")
            print(f"- Time    : {alert['ts']}")
            if alert['src_ip']: print(f"- Src IP  : {alert['src_ip']}")
            if alert['tactics']: print(f"- Tactics : {', '.join(alert['tactics'])}")
            print()
        except RuntimeError as e:
            print(f"\n  [!]  Skipped -- {e}")
            evidence = {"agent_status":"DISCONNECTED or unreachable",
                        "note":"Evidence unavailable -- analysis from chain only."}
        except Exception as e:
            print(f"\n  ERR  {type(e).__name__}: {e}")
            evidence = {"error":str(e)}
        if STOP_FLAG.is_set():
            print("\n  [Stopped by user]")
            break
        print(); call_llm(alert, evidence, chain)

    all_ips = {ip for c in chains.values() if c for ip in c["src_ips"]}
    if all_ips:
        print(f"\n{'-'*56}\n  SOURCE IPs\n{'-'*56}")
        for ip in sorted(all_ips):
            internal = any(ip.startswith(p) for p in
                ("10.","192.168.","172.16.","172.17.","172.18.","172.19.",
                 "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
                 "172.26.","172.27.","172.28.","172.29.","172.30.","172.31."))
            print(f"  {ip:22s}  {'internal' if internal else '[!]  EXTERNAL'}")
    print()

def main():
    p = argparse.ArgumentParser(description=f"Wazuh Correlation Agent [Ollama]")
    p.add_argument("--severity", type=int, default=MIN_SEV)
    p.add_argument("--hours",    type=int, default=HOURS)
    p.add_argument("--agent",    type=str, default=None)
    p.add_argument("--debug",    action="store_true")
    args = p.parse_args()
    if args.debug:
        global log; log = _setup_logger(debug=True)
        log.debug("Debug | model=%s | severity>=%d | hours=%d",
                  C["MODEL"], args.severity, args.hours)
    run(args.severity, args.hours, args.agent)

if __name__ == "__main__":
    main()
