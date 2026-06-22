import os
import sys
import json
import time
import logging
from datetime import datetime, timezone, timedelta

import ollama

import client as ag

log = logging.getLogger("agent")

AGENTIC_MODEL = ag.C["AGENTIC_MODEL"]
OL_HOST       = ag.C["OL_HOST"]
MAX_STEPS     = ag.C["AGENTIC_MAX_STEPS"]   # safety cap on the loop

_agent_cache = {}   # name/id (lower) -> id

def _resolve_agent(agent_id):
    """Accept an agent name or ID; return the real numeric ID string.
    Falls back to the input (zfilled) if nothing matches."""
    if not agent_id:
        return None
    key = str(agent_id).strip().lower()

    if key.isdigit():
        return key.zfill(3)

    if key in _agent_cache:
        return _agent_cache[key]

    # Build the map from the indexer (no Wazuh API dependency)
    try:
        agg = ag.ix_agg({"match_all": {}},
                        {"a": {"terms": {"field": "agent.name", "size": 50},
                               "aggs": {"id": {"terms": {"field": "agent.id", "size": 1}}}}})
        for b in agg.get("a", {}).get("buckets", []):
            idb = b.get("id", {}).get("buckets", [])
            if idb:
                aid = idb[0]["key"]
                _agent_cache[b["key"].lower()] = aid
                _agent_cache[aid.lower()]      = aid
    except Exception:
        pass

    return _agent_cache.get(key, str(agent_id).zfill(3))


# ──────────────────────────────────────────────────────────────────────────────
#  TOOL IMPLEMENTATIONS
# ──────────────────────────────────────────────────────────────────────────────

def _tool_search_alerts(query: str = "", hours: int = 24, agent_id: str = None,
                        min_level: int = 0):
    """Full-text search across alerts (wildcard, keyword-field safe)."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    must  = [{"range": {"timestamp": {"gte": since}}}]
    if agent_id:
        must.append({"term": {"agent.id": _resolve_agent(agent_id)}})
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    q_low  = (query or "").lower().strip()
    should = []
    if q_low:
        words = [w for w in q_low.split() if len(w) > 1]
        if len(words) > 1:
            should = [
                {"bool": {"must": [{"wildcard": {"rule.description":
                    {"value": f"*{w}*", "case_insensitive": True}}} for w in words]}},
                {"bool": {"must": [{"wildcard": {"full_log":
                    {"value": f"*{w}*", "case_insensitive": True}}} for w in words]}},
            ]
        else:
            should = [
                {"wildcard": {"rule.description":
                    {"value": f"*{q_low}*", "case_insensitive": True}}},
                {"wildcard": {"full_log":
                    {"value": f"*{q_low}*", "case_insensitive": True}}},
            ]
    bq = {"bool": {"must": must}}
    if should:
        bq["bool"]["should"] = should
        bq["bool"]["minimum_should_match"] = 1

    agg  = ag.ix_agg(bq, {"total": {"value_count": {"field": "rule.level"}},
                          "max_sev": {"max": {"field": "rule.level"}}})
    hits = ag.ix_search(bq, size=8, sort=[{"timestamp": {"order": "desc"}}])
    samples = [{
        "time":   (h.get("timestamp", "") or "")[:19],
        "agent":  (h.get("agent", {}) or {}).get("name", "?"),
        "level":  (h.get("rule", {}) or {}).get("level"),
        "desc":   (h.get("rule", {}) or {}).get("description", ""),
    } for h in hits.get("hits", [])]
    return {
        "total_matches": agg.get("total", {}).get("value", 0),
        "max_severity":  agg.get("max_sev", {}).get("value") or 0,
        "window_hours":  hours,
        "samples":       samples,
    }


def _tool_aggregate_alerts(group_by: str = "rule.groups", hours: int = 24,
                           agent_id: str = None, min_level: int = 0, size: int = 15):
    """Aggregate alert counts by a field to see the shape of activity."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    must  = [{"range": {"timestamp": {"gte": since}}}]
    if agent_id:
        must.append({"term": {"agent.id": _resolve_agent(agent_id)}})
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    bq = {"bool": {"must": must}}
    allowed = {"rule.groups", "rule.description", "agent.name", "agent.id",
               "rule.level", "rule.mitre.tactic", "rule.mitre.technique",
               "data.srcip", "data.win.eventdata.image"}
    # The model sometimes passes multiple comma-separated fields; take the
    # first valid one (single-field aggregation only) so it isn't silently wrong.
    requested = [f.strip() for f in str(group_by).split(",")]
    field = next((f for f in requested if f in allowed), "rule.groups")
    agg = ag.ix_agg(bq, {"g": {"terms": {"field": field, "size": size,
                                         "order": {"mx": "desc"}},
                               "aggs": {"mx": {"max": {"field": "rule.level"}}}}})
    buckets = [{"key": b["key"], "count": b["doc_count"],
                "max_level": b.get("mx", {}).get("value", 0)}
               for b in agg.get("g", {}).get("buckets", [])]
    return {"grouped_by": field, "window_hours": hours, "buckets": buckets}


def _tool_get_agent_timeline(agent_id: str, hours: int = 6, min_level: int = 0):
    """Chronological event timeline for one agent — for chain reconstruction."""
    if not agent_id:
        return {"error": "agent_id is required"}
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    must  = [{"range": {"timestamp": {"gte": since}}},
             {"term": {"agent.id": _resolve_agent(agent_id)}}]
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    hits = ag.ix_search({"bool": {"must": must}}, size=40,
                        sort=[{"timestamp": {"order": "asc"}}])
    events = [{
        "time":  (h.get("timestamp", "") or "")[:19],
        "level": (h.get("rule", {}) or {}).get("level"),
        "desc":  (h.get("rule", {}) or {}).get("description", ""),
        "tactic": (h.get("rule", {}) or {}).get("mitre", {}).get("tactic", []),
    } for h in hits.get("hits", [])]
    return {"agent": _resolve_agent(agent_id), "window_hours": hours,
            "event_count": len(events), "timeline": events[:40]}


def _tool_get_inventory(kind: str, agent_id: str):
    """Host inventory: packages | ports | processes | files (via syscollector).
    Returns the RAW inventory rows with no 'suspicious' flagging — the model
    inspects the actual names/ports/paths and decides what is concerning.
     """
    if kind not in ("packages", "ports", "processes", "files"):
        return {"error": f"kind must be packages/ports/processes/files, got {kind}"}
    res = ag.inventory(kind, _resolve_agent(agent_id))
    # inventory() already returns raw facts only — no judgment to strip.
    # Cap rows so a large host doesn't flood the model's context.
    rows = res.get("rows", [])
    if len(rows) > 50:
        res["rows"] = rows[:50]
        res["truncated"] = True
        res["total_rows"] = len(rows)
    return res


def _tool_get_rule_frequency(rule_groups: str, days: int = 30):

    rate  = ag._rule_baseline_freq(rule_groups, baseline_days=days)
    return {"rule_groups": rule_groups, "baseline_days": days,
            "events_per_day": round(rate, 2),
            "total_in_window": int(round(rate * days))}


def _tool_get_event_sequence(agent_id: str, around_time: str = None,
                            window_minutes: int = 30, min_level: int = 0):

    aid = _resolve_agent(agent_id)
    # Resolve the window. If a time is given, center on it; else last N minutes.
    try:
        if around_time:
            t = datetime.fromisoformat(around_time.replace("Z", "+00:00"))
        else:
            t = datetime.now(timezone.utc)
    except Exception:
        t = datetime.now(timezone.utc)
    lo = (t - timedelta(minutes=window_minutes)).isoformat()
    hi = (t + timedelta(minutes=window_minutes)).isoformat()

    must = [{"term": {"agent.id": aid}},
            {"range": {"timestamp": {"gte": lo, "lte": hi}}}]
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    raw = ag.ix_search({"bool": {"must": must}}, size=80,
                       sort=[{"timestamp": {"order": "asc"}}])

    seen, steps = set(), []
    for h in raw.get("hits", []):
        win = (h.get("data", {}) or {}).get("win", {}).get("eventdata", {}) or {}
        desc = (h.get("rule", {}) or {}).get("description", "")
        ts   = (h.get("timestamp", "") or "")[:19]
        # Dedup identical (description) repeats but keep first occurrence + count
        key = desc
        if key in seen:
            for s in steps:
                if s["event"] == desc:
                    s["repeat"] += 1
                    s["last_seen"] = ts
                    break
            continue
        seen.add(key)
        steps.append({
            "time":   ts,
            "level":  (h.get("rule", {}) or {}).get("level", 0),
            "event":  desc,
            "tactic": (h.get("rule", {}) or {}).get("mitre", {}).get("tactic", []),
            "process":     (win.get("image", "") or "").split("\\")[-1],
            "parent":      (win.get("parentImage", "") or "").split("\\")[-1],
            "command":     (win.get("commandLine", "") or "")[:160],
            "target_file": (win.get("targetFilename", win.get("targetFileName", "")) or "")[-80:],
            "reg_key":     (win.get("targetObject", "") or "")[-80:],
            "user":        win.get("user", ""),
            "src_ip":      (h.get("data", {}) or {}).get("srcip", ""),
            "repeat":      1,
            "last_seen":   ts,
        })
    return {"agent": aid, "window_minutes": window_minutes,
            "center_time": t.isoformat()[:19],
            "distinct_steps": len(steps),
            "sequence": steps[:50]}


def _tool_find_entity_across_agents(entity: str, hours: int = 168):
    """
    Cross-host correlation: find where a single indicator — an IP, file hash,
    username, process name, or domain — appears across ALL agents in the window.
    Use this to tell whether something is isolated to one host or part of a
    campaign spanning multiple hosts. Returns the per-agent breakdown plus a
    timeline span; YOU decide if the spread indicates a coordinated campaign.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    e = (entity or "").lower().strip()
    if not e:
        return {"error": "entity is required"}
    q = {"bool": {"must": [{"range": {"timestamp": {"gte": since}}}],
                  "should": [
                      {"wildcard": {"full_log": {"value": f"*{e}*", "case_insensitive": True}}},
                      {"wildcard": {"rule.description": {"value": f"*{e}*", "case_insensitive": True}}},
                      {"match": {"data.srcip": entity}},
                      {"match": {"data.win.eventdata.image": entity}},
                      {"match": {"data.win.eventdata.targetUserName": entity}},
                  ],
                  "minimum_should_match": 1}}
    agg = ag.ix_agg(q, {
        "total":  {"value_count": {"field": "rule.level"}},
        "agents": {"terms": {"field": "agent.name", "size": 30},
                   "aggs": {"id":    {"terms": {"field": "agent.id", "size": 1}},
                            "first": {"min": {"field": "timestamp"}},
                            "last":  {"max": {"field": "timestamp"}},
                            "mx":    {"max": {"field": "rule.level"}}}},
    })
    agents = []
    for b in agg.get("agents", {}).get("buckets", []):
        idb = b.get("id", {}).get("buckets", [])
        agents.append({
            "agent":      b["key"],
            "id":         idb[0]["key"] if idb else "?",
            "hits":       b["doc_count"],
            "first_seen": (b.get("first", {}).get("value_as_string", "") or "")[:19],
            "last_seen":  (b.get("last", {}).get("value_as_string", "") or "")[:19],
            "max_level":  b.get("mx", {}).get("value") or 0,
        })
    return {"entity": entity, "window_hours": hours,
            "total_hits": agg.get("total", {}).get("value", 0),
            "agents_affected": len(agents),
            "per_agent": agents}


def _tool_get_vulnerabilities(agent_id: str = None, days: int = 30):

    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    must = [{"range": {"timestamp": {"gte": since}}},
            {"match": {"rule.groups": "vulnerability-detector"}}]
    if agent_id:
        must.append({"term": {"agent.id": _resolve_agent(agent_id)}})
    q = {"bool": {"must": must}}
    agg = ag.ix_agg(q, {
        "total":  {"value_count": {"field": "rule.level"}},
        "by_cve": {"terms": {"field": "rule.description", "size": 25,
                             "order": {"mx": "desc"}},
                   "aggs": {"mx": {"max": {"field": "rule.level"}},
                            "agents": {"terms": {"field": "agent.name", "size": 5}}}},
    })
    cves = []
    for b in agg.get("by_cve", {}).get("buckets", []):
        cves.append({"description": b["key"], "count": b["doc_count"],
                     "max_level": b.get("mx", {}).get("value") or 0,
                     "agents": [x["key"] for x in b.get("agents", {}).get("buckets", [])]})
    return {"window_days": days, "scope": agent_id or "all agents",
            "total_findings": agg.get("total", {}).get("value", 0),
            "vulnerabilities": cves}


def _tool_get_active_agents(hours: int = 168):
    """Discover which agents have activity, straight from the indexer
    (no Wazuh API token needed — resilient to API auth hiccups)."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    agg = ag.ix_agg({"range": {"timestamp": {"gte": since}}},
                    {"agents": {"terms": {"field": "agent.name", "size": 30},
                                "aggs": {"id": {"terms": {"field": "agent.id", "size": 1}},
                                         "mx": {"max": {"field": "rule.level"}}}}})
    out = []
    for b in agg.get("agents", {}).get("buckets", []):
        idb = b.get("id", {}).get("buckets", [])
        out.append({"name": b["key"],
                    "id": idb[0]["key"] if idb else "?",
                    "event_count": b["doc_count"],
                    "max_level": b.get("mx", {}).get("value") or 0})
    return {"window_hours": hours, "active_agents": out}


def _tool_list_agents():
    """List enrolled agents and their status."""
    try:
        r = ag.wget("/agents", {"limit": 100,
                                "select": "id,name,status,os.platform,ip"})
        items = r.get("affected_items", [])
        return {"count": len(items),
                "agents": [{"id": a.get("id"), "name": a.get("name"),
                            "status": a.get("status"),
                            "os": (a.get("os", {}) or {}).get("platform", "?"),
                            "ip": a.get("ip")} for a in items]}
    except Exception as e:
        return {"error": str(e)}


# ── Tool registry: maps tool name → (function, JSON schema for the model) ──────
TOOLS = {
    "search_alerts": (_tool_search_alerts, {
        "type": "function",
        "function": {
            "name": "search_alerts",
            "description": "Search security alerts. query is OPTIONAL — omit it (or "
                           "pass empty) to match ALL alerts and filter only by "
                           "hours/agent_id/min_level (e.g. 'all severity-12 events'). "
                           "Provide a keyword/phrase/IP/hash to narrow. Returns "
                           "match count, max severity, and sample events.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query":     {"type": "string",
                                  "description": "Keyword/phrase/IP/hash to search"},
                    "hours":     {"type": "integer",
                                  "description": "Look-back window in hours (default 24)"},
                    "agent_id":  {"type": "string",
                                  "description": "Optional agent ID to scope to one host"},
                    "min_level": {"type": "integer",
                                  "description": "Optional minimum Wazuh severity (0-15)"},
                },
                "required": [],
            },
        },
    }),
    "aggregate_alerts": (_tool_aggregate_alerts, {
        "type": "function",
        "function": {
            "name": "aggregate_alerts",
            "description": "Aggregate alert counts grouped by a field to see the "
                           "overall shape of activity (which rule groups, agents, "
                           "tactics, or source IPs are most active). Use this for "
                           "an overview before drilling in.",
            "parameters": {
                "type": "object",
                "properties": {
                    "group_by":  {"type": "string",
                                  "description": "ONE field only (not a list): rule.groups, "
                                  "rule.description, agent.name, agent.id, "
                                  "rule.mitre.tactic, or data.srcip"},
                    "hours":     {"type": "integer"},
                    "agent_id":  {"type": "string"},
                    "min_level": {"type": "integer"},
                },
                "required": ["group_by"],
            },
        },
    }),
    "get_agent_timeline": (_tool_get_agent_timeline, {
        "type": "function",
        "function": {
            "name": "get_agent_timeline",
            "description": "Get the chronological event timeline for ONE agent. "
                           "Use this to reconstruct what happened on a host in "
                           "sequence — essential for understanding an attack chain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id":  {"type": "string", "description": "Agent ID (required)"},
                    "hours":     {"type": "integer", "description": "Window (default 6)"},
                    "min_level": {"type": "integer"},
                },
                "required": ["agent_id"],
            },
        },
    }),
    "get_inventory": (_tool_get_inventory, {
        "type": "function",
        "function": {
            "name": "get_inventory",
            "description": "Get the raw host inventory for one agent: installed "
                           "packages, open ports, running processes, or recently "
                           "changed files. Returns the actual names/ports/paths "
                           "with no pre-filtering — YOU inspect them and decide "
                           "what is unusual for this host.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind":     {"type": "string",
                                 "description": "packages | ports | processes | files"},
                    "agent_id": {"type": "string", "description": "Agent ID (required)"},
                },
                "required": ["kind", "agent_id"],
            },
        },
    }),
    "get_rule_frequency": (_tool_get_rule_frequency, {
        "type": "function",
        "function": {
            "name": "get_rule_frequency",
            "description": "Get how often a rule group fires per day over a baseline "
                           "window (raw events/day and window total). Use the "
                           "numbers to judge for yourself whether a rate is "
                           "routine for this environment or unusual.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_groups": {"type": "string",
                                    "description": "The rule.groups value to baseline"},
                    "days":        {"type": "integer", "description": "Baseline days (default 30)"},
                },
                "required": ["rule_groups"],
            },
        },
    }),
    "get_event_sequence": (_tool_get_event_sequence, {
        "type": "function",
        "function": {
            "name": "get_event_sequence",
            "description": "Reconstruct the distinct, time-ordered event sequence "
                           "on ONE host within a window — with process lineage "
                           "(process, parent, command line), file/registry targets, "
                           "user, and source IP. This is the tool for CHAIN analysis: "
                           "use it to see what action led to what. Center it on a "
                           "suspicious event's timestamp (around_time) to see what "
                           "happened just before and after.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id":       {"type": "string", "description": "Agent ID (required)"},
                    "around_time":    {"type": "string",
                                       "description": "ISO timestamp to center the window on "
                                       "(e.g. from a suspicious event). Omit for most recent."},
                    "window_minutes": {"type": "integer",
                                       "description": "Half-window each side (default 30)"},
                    "min_level":      {"type": "integer"},
                },
                "required": ["agent_id"],
            },
        },
    }),
    "find_entity_across_agents": (_tool_find_entity_across_agents, {
        "type": "function",
        "function": {
            "name": "find_entity_across_agents",
            "description": "Cross-host correlation: find where a single indicator "
                           "(IP, file hash, username, process name, or domain) "
                           "appears across ALL agents in the window, with a per-host "
                           "breakdown and first/last-seen times. Use this to decide "
                           "whether activity is isolated to one host or part of a "
                           "campaign spanning multiple hosts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity": {"type": "string",
                               "description": "The indicator: IP, hash, username, "
                               "process name, or domain"},
                    "hours":  {"type": "integer", "description": "Window (default 168)"},
                },
                "required": ["entity"],
            },
        },
    }),
    "get_vulnerabilities": (_tool_get_vulnerabilities, {
        "type": "function",
        "function": {
            "name": "get_vulnerabilities",
            "description": "List detected CVE vulnerabilities from Wazuh's "
                           "vulnerability-detector (read from the indexer, always "
                           "available). Optionally scope to one agent. Use this for "
                           "any question about vulnerabilities, CVEs, or patch gaps. "
                           "Returns CVE descriptions, severities, and affected hosts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string",
                                 "description": "Optional — scope to one agent"},
                    "days":     {"type": "integer", "description": "Window (default 30)"},
                },
            },
        },
    }),
    "get_active_agents": (_tool_get_active_agents, {
        "type": "function",
        "function": {
            "name": "get_active_agents",
            "description": "List agents that have activity in the window, with "
                           "their event counts and max severity — read straight "
                           "from the indexer (always available, even if the Wazuh "
                           "API is briefly down). Prefer this over list_agents for "
                           "finding which hosts to investigate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {"type": "integer",
                              "description": "Look-back window (default 168 = 7 days)"},
                },
            },
        },
    }),
    "list_agents": (_tool_list_agents, {
        "type": "function",
        "function": {
            "name": "list_agents",
            "description": "List all enrolled agents with their status, OS, and IP. "
                           "Use this when you need to know which hosts exist.",
            "parameters": {"type": "object", "properties": {}},
        },
    }),
}

TOOL_SCHEMAS = [schema for (_fn, schema) in TOOLS.values()]


# ──────────────────────────────────────────────────────────────────────────────
#  THE AGENTIC LOOP
# ──────────────────────────────────────────────────────────────────────────────

def _build_system_prompt(mgr_name=None, notes=None):
    _mgr = mgr_name.strip() if mgr_name else ""
    _notes = (notes or "").strip()
    _notes_section = (
        "\nENVIRONMENT CONTEXT — additional context provided by the operator:\n"
        + _notes + "\n"
    ) if _notes else ""
    return (
    "You are an autonomous SOC analyst investigating a security question against "
    "a Wazuh deployment. You have tools to search alerts, aggregate them, pull a "
    "host's timeline, read host inventory, check rule baselines, and list agents.\n\n"
    "WAZUH INFRASTRUCTURE — critical: In Wazuh, agent ID 000 is the Wazuh manager "
    "node and also the collection point for ALL agentless/API-based integrations "
    "(Office 365, AWS CloudTrail, Azure, GCP, GitHub, Slack, etc.). This means the "
    "vast majority of alerts under agent ID 000 are about events in those cloud "
    "services — they are NOT attacks on the manager host itself.\n"
    f"{'The manager hostname is ' + repr(_mgr) + '. ' if _mgr else ''}"
    "To decide whether an alert concerns the manager OS/host or a cloud integration, "
    "look at the rule group: groups like 'office365', 'aws', 'azure', 'gcp', 'github' "
    "mean the alert is about that cloud service, collected via integration — the "
    "manager is just the relay. Only rule groups such as 'syscheck', 'rootcheck', "
    "'authentication_failed', 'sshd', 'pam', 'ossec' with agent ID 000 indicate "
    "something happening on the manager OS itself. Never conclude the manager is "
    "'under attack' solely because alerts carry agent ID 000 — always check the "
    "rule group first to identify the actual source system.\n"
    + _notes_section +
    "\nWork iteratively: decide which tool to call, read the result, then decide if "
    "you need more data or can conclude. Prefer starting broad (aggregate or "
    "search) then drilling into specific agents and timelines.\n\n"
    "TIME WINDOWS — critical: if the user gives no timeframe, default to a BROAD "
    "window (720 hours / 30 days), not 24 hours. Threats commonly span days to "
    "weeks. If any search or timeline returns 0 results, DO NOT conclude 'nothing "
    "found' — widen the window (e.g. 24h -> 7d -> 30d) and try again. Only call "
    "something clean after looking across a genuinely broad window. When the user "
    "names a window (e.g. '20 days'), use it consistently across ALL your tool "
    "calls — do not silently narrow it to 24h on follow-up calls.\n\n"
    "CONVERGE — do not investigate forever. You typically have enough to "
    "conclude after 6-10 well-chosen tool calls. Once you have established the "
    "main chain and checked whether key indicators are cross-host, STOP and write "
    "the answer. Do NOT chase every minor string (test artifacts, localhost, "
    "individual usernames) — focus on the strongest 2-3 leads. It is better to "
    "deliver a clear answer on the main finding than to exhaustively probe every "
    "detail and run out of steps.\n\n"
    "INVESTIGATE, do not delegate. You have a limited number of tool calls — "
    "spend them on the strongest leads. "
    "Do NOT end by telling the analyst to 'investigate further', 'check the "
    "timeline', or 'review group X'. If something is worth investigating, YOU "
    "investigate it now with another tool call. Only stop when you have actually "
    "looked, not when you have identified what could be looked at.\n\n"
    "CORRELATION means reconstructing the story across events — not counting "
    "them. When asked to correlate, or when you find a cluster of related "
    "alerts:\n"
    "- Use get_event_sequence centered on a suspicious timestamp to see the "
    "ordered chain on that host (what process spawned what, which file/registry "
    "was touched, by which user). Describe the sequence: X led to Y led to Z.\n"
    "- Use find_entity_across_agents on any shared indicator (an IP, user, hash, "
    "or process name you saw) to check if the SAME thing appears on other hosts "
    "— that distinguishes an isolated incident from a campaign spanning hosts.\n"
    "- A good correlation answer names the specific events in order, the entities "
    "linking them, and what attack chain the sequence represents — not just totals.\n\n"
    "Pursue every strong lead before concluding. Specifically:\n"
    "- If any rule group shows max_level >= 12, drill in: search_alerts or "
    "aggregate by agent.name within that group, then pull the agent's timeline.\n"
    "- If activity looks high-volume, call get_rule_frequency to decide if it is "
    "routine noise or a real spike — do not guess.\n"
    "- If a specific host stands out, get_agent_timeline and, if relevant, "
    "get_inventory (processes/ports) on it.\n"
    "- Follow the evidence across at least 2-3 tools before any verdict on a lead.\n\n"
    "The tools return raw facts only — counts, rates, severities, names, "
    "timestamps. They do NOT tell you what is malicious or noisy; that judgment "
    "is YOURS. A high events/day rate may be benign in one environment and "
    "alarming in another — reason about it, don't assume.\n\n"
    "When you have genuinely exhausted the leads, write a final answer with: a "
    "clear verdict, the specific evidence you gathered (counts, agents, severities, "
    "timestamps from YOUR tool calls), and what it means. Recommendations are fine "
    "only AFTER you have done the investigation yourself. Be precise and cite the "
    "numbers your tools returned. Plain text, no markdown headers."
)

SYSTEM_PROMPT = _build_system_prompt()


def run_agent(question: str, agent_id: str = None, emit=None, context=None):
    """
    Run the agentic investigation loop.

    question : the analyst's natural-language question
    agent_id : optional scope hint passed into the first user message
    emit     : optional callback(event_type, payload) for streaming to a UI.
               event_type is one of: 'thinking', 'tool_call', 'tool_result',
               'answer', 'done', 'error'. If None, prints to stdout.
    context  : optional dict with keys 'manager_name' and 'notes' from the
               Context tab; overrides WAZUH_MANAGER_NAME from .env.

    Returns the final answer string.
    """
    def _emit(kind, payload):
        if emit:
            emit(kind, payload)
        else:
            if kind == "thinking":
                # Show a short preview of the model's reasoning between calls
                preview = payload[:200].replace("\n", " ")
                print(f"\n  ~ {preview}{'...' if len(payload) > 200 else ''}")
            elif kind == "tool_call":
                print(f"\n  → TOOL: {payload['name']}({json.dumps(payload['args'])})")
            elif kind == "tool_result":
                preview = json.dumps(payload["result"])[:300]
                print(f"  ← {preview}{'...' if len(preview) >= 300 else ''}")
            elif kind == "answer":
                print(f"\n{payload}")
            elif kind == "error":
                print(f"\n[ERROR] {payload}")

    client = ollama.Client(host=OL_HOST)

    ctx = context or {}
    system_prompt = _build_system_prompt(
        mgr_name=ctx.get("manager_name"),
        notes=ctx.get("notes"),
    )

    user_msg = question
    if agent_id:
        user_msg = f"(Focus on agent {agent_id}.) {question}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_msg},
    ]

    audit = []   # full record of every tool call, for the SIEM trail

    for step in range(MAX_STEPS):
        if ag.STOP_FLAG.is_set():
            _emit("error", "Stopped by user.")
            return "[stopped]"

        try:
            resp = client.chat(
                model=AGENTIC_MODEL,
                messages=messages,
                tools=TOOL_SCHEMAS,
                options={"temperature": 0, "num_ctx": 16384},
            )
        except Exception as e:
            _emit("error", f"Model call failed: {e}")
            return f"[error: {e}]"

        if ag.STOP_FLAG.is_set():
            _emit("error", "Stopped by user.")
            return "[stopped]"

        msg = resp.message
        tool_calls = getattr(msg, "tool_calls", None) or []

        # No tool calls → the model is giving its final answer
        if not tool_calls:
            answer = msg.content or "(no answer)"
            _emit("answer", answer)
            _emit("done", {"steps": step, "audit": audit})
            return answer

        # Append the assistant turn (with its tool-call requests) to history.
        # If the model also emitted reasoning text, surface it (it often
        # contains the running hypothesis) so nothing is silently dropped.
        if msg.content and msg.content.strip():
            _emit("thinking", msg.content.strip())
        messages.append({"role": "assistant", "content": msg.content or "",
                         "tool_calls": tool_calls})

        # Execute each requested tool
        for tc in tool_calls:
            name = tc.function.name
            args = tc.function.arguments
            if isinstance(args, str):
                try:    args = json.loads(args)
                except Exception: args = {}

            if ag.STOP_FLAG.is_set():
                _emit("error", "Stopped by user.")
                return "[stopped]"

            _emit("tool_call", {"name": name, "args": args})
            audit.append({"step": step, "tool": name, "args": args,
                          "ts": datetime.now().isoformat()})

            entry = TOOLS.get(name)
            if not entry:
                result = {"error": f"unknown tool {name}"}
            else:
                fn = entry[0]
                try:
                    result = fn(**args)
                except TypeError as e:
                    result = {"error": f"bad arguments: {e}"}
                except Exception as e:
                    log.exception("Tool %s failed", name)
                    result = {"error": str(e)}

            _emit("tool_result", {"name": name, "result": result})

            messages.append({"role": "tool", "name": name,
                             "content": json.dumps(result)[:4000]})

    # Hit the step cap — force a final text answer.
    # Crucially: do NOT pass tools, so the model cannot ask for more calls and
    # must produce prose. Retry once if it still comes back empty.
    messages.append({"role": "user",
                     "content": "STOP investigating now — you have reached the "
                                "step limit. Do NOT request any more tools. Based "
                                "ONLY on the evidence already gathered above, write "
                                "your complete final answer now: verdict, the "
                                "specific events/entities/timestamps you found, what "
                                "attack chain they represent, and recommended actions."})
    answer = ""
    for _try in range(2):
        try:
            resp = client.chat(model=AGENTIC_MODEL, messages=messages,
                               options={"temperature": 0, "num_predict": 1200})
            answer = (resp.message.content or "").strip()
            if answer:
                break
            # Empty — nudge harder
            messages.append({"role": "user",
                             "content": "Write the final answer as plain text now."})
        except Exception as e:
            answer = f"[error producing final answer: {e}]"
            break
    if not answer:
        answer = ("[The investigation gathered evidence across "
                  + str(len(audit)) + " tool calls but did not produce a final "
                  "summary within the step limit. See the tool-call audit for "
                  "the raw findings.]")
    _emit("answer", answer)
    _emit("done", {"steps": MAX_STEPS, "audit": audit, "capped": True})
    return answer


# ── CLI for standalone testing (before any UI wiring) ─────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s  %(levelname)s  %(message)s")
    args = sys.argv[1:]
    agent = None
    if "--agent" in args:
        i = args.index("--agent")
        agent = args[i + 1]
        args = args[:i] + args[i + 2:]
    question = " ".join(args) or "Are there any signs of compromise in the last 24 hours?"

    print(f"Model    : {AGENTIC_MODEL}")
    print(f"Ollama   : {OL_HOST}")
    print(f"Question : {question}")
    if agent:
        print(f"Agent    : {agent}")
    print("─" * 60)

    t0 = time.perf_counter()
    run_agent(question, agent_id=agent)
    print("─" * 60)
    print(f"Completed in {int(time.perf_counter() - t0)}s")