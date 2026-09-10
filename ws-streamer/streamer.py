#!/usr/bin/env python3
"""
Real-time WebSocket Alert Streamer
Polls OpenSearch every 5 seconds, pushes new alerts to all connected dashboard clients.
Used by the SOC Overview and all HTML dashboards for live alert feeds.
"""
import asyncio
import websockets
import json
import os
import logging
from datetime import datetime, timedelta, timezone
from opensearchpy import OpenSearch, OpenSearchException
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WS-STREAMER] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# Config from env
OS_HOST   = os.getenv("OPENSEARCH_HOST", "opensearch-node1")
OS_PORT   = int(os.getenv("OPENSEARCH_PORT", "9200"))
OS_USER   = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS   = os.getenv("OPENSEARCH_PASSWORD", "AdminPassword123!")
WS_HOST   = os.getenv("WS_HOST", "0.0.0.0")
WS_PORT   = int(os.getenv("WS_PORT", "8765"))
HTTP_PORT = int(os.getenv("WS_HTTP_PORT", "8766"))
POLL_SECS = int(os.getenv("POLL_INTERVAL_SECS", "5"))
CREWAI_URL = os.getenv("CREWAI_URL", "http://crewai-soc:8500")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
IRIS_URL = os.getenv("IRIS_URL", "https://dfir-iris:443")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
MISP_URL = os.getenv("MISP_URL", "https://misp:443")
MISP_KEY = os.getenv("MISP_KEY", "")
CALDERA_URL = os.getenv("CALDERA_URL_INTERNAL", "http://caldera:8888")

# Connected client registry
CLIENTS: set = set()

# Watermark — only push events newer than this
last_seen_ts: str = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()


def get_os_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=False,
        verify_certs=False,
        retry_on_timeout=True,
    )


def fetch_new_alerts(client: OpenSearch) -> list[dict]:
    """Poll OpenSearch for alerts newer than last_seen_ts."""
    global last_seen_ts
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": last_seen_ts}}},
                ],
                "should": [
                    # Vector's transforms all nest this as mitre.technique
                    # (an object field), never a flat top-level
                    # "mitre_technique" - that field never existed, so this
                    # clause never matched anything.
                    {"exists": {"field": "mitre.technique"}},
                    {"term": {"event_type.keyword": "alert"}},
                    {"term": {"log_type.keyword": "suricata"}},
                    {"term": {"log_type.keyword": "wazuh"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 50,
    }
    try:
        resp = client.search(index="soc-logs-*", body=body)
        hits = resp["hits"]["hits"]
        alerts = []
        for h in hits:
            s = h["_source"]
            alerts.append({
                "id": h["_id"],
                "timestamp": s.get("@timestamp"),
                "type": s.get("event_type") or s.get("log_type") or "event",
                "mitre_tactic": s.get("mitre_tactic", ""),
                "mitre_technique": (s.get("mitre") or {}).get("technique", ""),
                "severity": s.get("severity") or (s.get("alert") or {}).get("severity", "medium"),
                "src_ip": s.get("src_ip") or (s.get("source") or {}).get("ip", "") or (s.get("agent") or {}).get("ip", ""),
                "dest_ip": s.get("dest_ip") or (s.get("destination") or {}).get("ip", ""),
                "hostname": s.get("hostname") or (s.get("host") or {}).get("name", ""),
                "message": s.get("message") or (s.get("alert") or {}).get("signature", ""),
                "sensor": s.get("sensor_type", "unknown"),
            })
        if alerts:
            last_seen_ts = alerts[-1]["timestamp"]
            log.info(f"Fetched {len(alerts)} new alerts")
        return alerts
    except OpenSearchException as e:
        log.warning(f"OpenSearch poll error: {e}")
        return []


async def broadcast(message: str):
    """Send message to all connected WebSocket clients."""
    global CLIENTS
    if not CLIENTS:
        return
    dead = set()
    for ws in CLIENTS.copy():
        try:
            await ws.send(message)
        except websockets.exceptions.ConnectionClosed:
            dead.add(ws)
    CLIENTS -= dead


async def poll_loop():
    """Background task: poll OpenSearch and broadcast new alerts."""
    client = None
    while True:
        await asyncio.sleep(POLL_SECS)
        try:
            if client is None:
                client = get_os_client()
            alerts = fetch_new_alerts(client)
            if alerts:
                payload = json.dumps({
                    "type": "alerts",
                    "count": len(alerts),
                    "alerts": alerts,
                    "server_time": datetime.now(timezone.utc).isoformat(),
                })
                await broadcast(payload)
        except Exception as e:
            log.error(f"Poll loop error: {e}")
            client = None  # force reconnect


async def heartbeat_loop():
    """Send heartbeat every 30s so dashboards know the stream is alive."""
    while True:
        await asyncio.sleep(30)
        hb = json.dumps({
            "type": "heartbeat",
            "server_time": datetime.now(timezone.utc).isoformat(),
            "connected_clients": len(CLIENTS),
        })
        await broadcast(hb)


async def handler(websocket):
    """Handle new WebSocket connection."""
    client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    log.info(f"Client connected: {client_ip} | total: {len(CLIENTS)+1}")
    CLIENTS.add(websocket)

    # Send welcome + stats burst
    try:
        os_client = get_os_client()
        # Last 1h stats
        resp = os_client.count(index="soc-logs-*", body={
            "query": {"range": {"@timestamp": {"gte": "now-1h"}}}
        })
        welcome = json.dumps({
            "type": "welcome",
            "message": "Connected to SOC Alert Stream",
            "events_last_1h": resp.get("count", 0),
            "server_time": datetime.now(timezone.utc).isoformat(),
        })
        await websocket.send(welcome)
    except Exception:
        pass

    try:
        async for _ in websocket:
            pass  # clients can send pings; we don't process commands
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        CLIENTS.discard(websocket)
        log.info(f"Client disconnected: {client_ip} | total: {len(CLIENTS)}")


# ── HTTP API (dashboard drilldowns: feed/charts/tables/single-event) ──
# The dashboards are static HTML with no server of their own - rather than
# ship OpenSearch's admin password to every browser so pages can query it
# directly, this process (which already holds that password server-side)
# proxies a small set of read-only, purpose-built queries instead.

SURICATA_FILTER = [
    {"term": {"log_type.keyword": "suricata"}},
    {"exists": {"field": "alert"}},
]

ZEEK_FILTER = [{"term": {"log_type.keyword": "zeek"}}]
# Zeek's own JSON logs don't carry a log-type tag (no "_path" field with
# this version's json-logs tuning) - conn.log/dns.log/notice.log entries
# are told apart by which fields they actually carry.
ZEEK_CONN_FILTER   = ZEEK_FILTER + [{"exists": {"field": "conn_state"}}]
ZEEK_DNS_FILTER    = ZEEK_FILTER + [{"exists": {"field": "query"}}]
ZEEK_NOTICE_FILTER = ZEEK_FILTER + [{"exists": {"field": "note"}}]
# LLMNR is UDP/5355, NBT-NS is UDP/137 - true poisoning/probe traffic on
# those ports, not the constant mDNS (5353) chatter phones/smart-TVs make.
ZEEK_LLMNR_FILTER  = ZEEK_DNS_FILTER + [{"terms": {"id.resp_p": [5355, 137]}}]

WAZUH_FILTER = [{"term": {"log_type.keyword": "wazuh"}}]
WAZUH_FIM_FILTER = WAZUH_FILTER + [{"term": {"rule.groups.keyword": "syscheck"}}]


@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        resp = web.Response()
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    return resp


async def handle_suricata_feed(request):
    client = get_os_client()
    limit = min(int(request.query.get("limit", 20)), 100)
    body = {
        "query": {"bool": {"filter": SURICATA_FILTER}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": limit,
    }
    resp = client.search(index="soc-logs-*", body=body)
    hits = [{"id": h["_id"], **h["_source"]} for h in resp["hits"]["hits"]]
    return web.json_response(hits)


async def handle_suricata_summary(request):
    client = get_os_client()

    def count(extra_filters):
        return client.count(index="soc-logs-*", body={
            "query": {"bool": {"filter": SURICATA_FILTER + [
                {"range": {"@timestamp": {"gte": "now-24h"}}}
            ] + extra_filters}}
        })["count"]

    alerts_24h = count([])
    blocked_24h = count([{"term": {"alert.action.keyword": "blocked"}}])

    agg_resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": SURICATA_FILTER + [
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        "aggs": {
            "sigs": {"cardinality": {"field": "rule.id"}},
            "ips": {"cardinality": {"field": "src_ip.keyword"}},
        },
    })
    return web.json_response({
        "alerts_24h": alerts_24h,
        "blocked_24h": blocked_24h,
        "unique_signatures_24h": agg_resp["aggregations"]["sigs"]["value"],
        "unique_src_ips_24h": agg_resp["aggregations"]["ips"]["value"],
    })


async def handle_suricata_categories(request):
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": SURICATA_FILTER + [
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        "aggs": {"cats": {"terms": {"field": "rule.category.keyword", "size": 10}}},
    })
    buckets = resp["aggregations"]["cats"]["buckets"]
    return web.json_response([{"category": b["key"], "count": b["doc_count"]} for b in buckets])


async def handle_suricata_timeline(request):
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": SURICATA_FILTER + [
            {"range": {"@timestamp": {"gte": "now-30m"}}}
        ]}},
        "aggs": {"tl": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": "1m", "min_doc_count": 0,
            "extended_bounds": {"min": "now-30m", "max": "now"},
        }}},
    })
    buckets = resp["aggregations"]["tl"]["buckets"]
    return web.json_response([{"time": b["key_as_string"], "count": b["doc_count"]} for b in buckets])


async def handle_suricata_top_signatures(request):
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": SURICATA_FILTER + [
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        "aggs": {"sigs": {
            "terms": {"field": "rule.id", "size": 10, "order": {"_count": "desc"}},
            "aggs": {"top": {"top_hits": {
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": ["rule.name", "rule.category", "rule.severity", "alert.action", "@timestamp"],
            }}},
        }},
    })
    out = []
    for b in resp["aggregations"]["sigs"]["buckets"]:
        top_hit = b["top"]["hits"]["hits"][0]
        top = top_hit["_source"]
        rule = top.get("rule", {})
        out.append({
            "sid": b["key"],
            "id": top_hit["_id"],
            "signature": rule.get("name", ""),
            "category": rule.get("category", ""),
            "count": b["doc_count"],
            "last_seen": top.get("@timestamp"),
            "action": (top.get("alert") or {}).get("action", "allowed"),
        })
    return web.json_response(out)


# NOTE on LLMNR/NBT-NS "poisoning": an earlier version of this tried to
# flag it by grouping port 5355/137 traffic by id.resp_h and looking for
# one IP answering many different names. That was still wrong - Zeek's
# dns.log record here captures the QUERY going out to the standard
# LLMNR/NBT-NS multicast/broadcast group (224.0.0.252, ff02::1:3,
# 192.168.x.255), not a spoofed unicast reply from an attacker, so
# id.resp_h is almost always that same multicast/broadcast address for
# every legitimate machine on the LAN - it can never distinguish a real
# Responder-style attack from ordinary Windows name-resolution fallback.
# Detecting an actual spoofed answer needs packet-content inspection,
# which is exactly what Suricata's ET POLICY LLMNR signatures already do
# (see the Suricata IDS dashboard) - don't reinvent it here from
# connection metadata. This panel is intentionally just query volume.


async def handle_zeek_summary(request):
    client = get_os_client()

    def count(filt):
        return client.count(index="soc-logs-*", body={
            "query": {"bool": {"filter": filt + [{"range": {"@timestamp": {"gte": "now-1h"}}}]}}
        })["count"]

    connections_1h = count(ZEEK_CONN_FILTER)
    notices_1h = count(ZEEK_NOTICE_FILTER)
    llmnr_1h = count(ZEEK_LLMNR_FILTER)

    dns_resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": ZEEK_DNS_FILTER + [{"range": {"@timestamp": {"gte": "now-1h"}}}]}},
        "aggs": {"uniq": {"cardinality": {"field": "query.keyword"}}},
    })
    return web.json_response({
        "connections_1h": connections_1h,
        "notices_1h": notices_1h,
        "dns_queries_1h": dns_resp["aggregations"]["uniq"]["value"],
        "llmnr_1h": llmnr_1h,
    })


async def handle_zeek_conn_feed(request):
    client = get_os_client()
    limit = min(int(request.query.get("limit", 30)), 100)
    resp = client.search(index="soc-logs-*", body={
        "query": {"bool": {"filter": ZEEK_CONN_FILTER}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": limit,
    })
    out = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        out.append({
            "id": h["_id"],
            "timestamp": s.get("@timestamp"),
            "orig_h": s.get("id.orig_h"), "orig_p": s.get("id.orig_p"),
            "resp_h": s.get("id.resp_h"), "resp_p": s.get("id.resp_p"),
            "proto": s.get("proto"), "service": s.get("service"),
            "orig_bytes": s.get("orig_bytes", 0), "resp_bytes": s.get("resp_bytes", 0),
            "conn_state": s.get("conn_state"),
        })
    return web.json_response(out)


async def handle_zeek_protocol_mix(request):
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": ZEEK_CONN_FILTER + [{"range": {"@timestamp": {"gte": "now-1h"}}}]}},
        "aggs": {"svc": {"terms": {"field": "service.keyword", "size": 10, "missing": "other"}}},
    })
    buckets = resp["aggregations"]["svc"]["buckets"]
    return web.json_response([{"protocol": b["key"], "count": b["doc_count"]} for b in buckets])


async def handle_zeek_dns_anomalies(request):
    """Heuristic flags, not a full detection engine: long/TXT queries (possible
    tunneling), WPAD probes, and .onion lookups (Tor). Real anomalies only -
    if none of these patterns occurred, this returns an empty list."""
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "query": {"bool": {
            "filter": ZEEK_DNS_FILTER + [{"range": {"@timestamp": {"gte": "now-1h"}}}],
            "should": [
                {"term": {"qtype_name.keyword": "TXT"}},
                {"wildcard": {"query.keyword": "*wpad*"}},
                {"wildcard": {"query.keyword": "*.onion*"}},
                {"script": {"script": "doc['query.keyword'].size() > 0 && doc['query.keyword'].value.length() > 50"}},
            ],
            "minimum_should_match": 1,
        }},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 10,
    })
    out = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        q = s.get("query", "")
        qtype = s.get("qtype_name", "")
        reason = ("DNS Tunnel" if qtype == "TXT" or len(q) > 50
                   else "WPAD Probe" if "wpad" in q.lower()
                   else "Tor Relay" if ".onion" in q.lower()
                   else "Flagged")
        out.append({"id": h["_id"], "query": q, "qtype": qtype, "reason": reason, "timestamp": s.get("@timestamp")})
    return web.json_response(out)


async def handle_zeek_llmnr(request):
    """Real LLMNR/NBT-NS query volume - who queried what, and which
    multicast/broadcast group it went to. Deliberately NOT labeled as
    poisoning (see the NOTE above handle_zeek_summary) - genuine
    spoofed-response detection belongs to Suricata's ET POLICY LLMNR
    signatures, not this endpoint."""
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "query": {"bool": {"filter": ZEEK_LLMNR_FILTER + [{"range": {"@timestamp": {"gte": "now-1h"}}}]}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 10,
    })
    out = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        out.append({
            "id": h["_id"], "timestamp": s.get("@timestamp"),
            "querier": s.get("id.orig_h"), "destination": s.get("id.resp_h"),
            "resource": s.get("query", ""),
        })
    return web.json_response(out)


async def handle_wazuh_summary(request):
    client = get_os_client()

    def count(filt):
        return client.count(index="soc-logs-*", body={
            "query": {"bool": {"filter": filt + [{"range": {"@timestamp": {"gte": "now-24h"}}}]}}
        })["count"]

    total_24h = count(WAZUH_FILTER)
    critical_24h = client.count(index="soc-logs-*", body={
        "query": {"bool": {"filter": WAZUH_FILTER + [
            {"range": {"@timestamp": {"gte": "now-24h"}}},
            {"range": {"rule.level": {"gte": 12}}},
        ]}}
    })["count"]
    fim_24h = count(WAZUH_FIM_FILTER)

    agents_resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": WAZUH_FILTER + [{"range": {"@timestamp": {"gte": "now-24h"}}}]}},
        "aggs": {"agents": {"cardinality": {"field": "agent.id.keyword"}}},
    })
    return web.json_response({
        "agents_active": agents_resp["aggregations"]["agents"]["value"],
        "critical_alerts_24h": critical_24h,
        "total_alerts_24h": total_24h,
        "fim_events_24h": fim_24h,
    })


async def handle_wazuh_feed(request):
    client = get_os_client()
    limit = min(int(request.query.get("limit", 20)), 100)
    resp = client.search(index="soc-logs-*", body={
        "query": {"bool": {"filter": WAZUH_FILTER}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": limit,
    })
    out = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        rule = s.get("rule", {})
        out.append({
            "id": h["_id"],
            "timestamp": s.get("@timestamp"),
            "level": rule.get("level"),
            "agent": (s.get("agent") or {}).get("name", ""),
            "rule_id": rule.get("id"),
            "description": rule.get("description", ""),
            "mitre_technique": (s.get("mitre") or {}).get("technique", "N/A"),
        })
    return web.json_response(out)


async def handle_wazuh_agents(request):
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={
        "size": 0,
        "query": {"bool": {"filter": WAZUH_FILTER + [{"range": {"@timestamp": {"gte": "now-7d"}}}]}},
        "aggs": {"agents": {
            "terms": {"field": "agent.id.keyword", "size": 50},
            "aggs": {
                "last_seen": {"max": {"field": "@timestamp"}},
                "name": {"top_hits": {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}], "_source": ["agent.name", "agent.ip"]}},
            },
        }},
    })
    out = []
    for b in resp["aggregations"]["agents"]["buckets"]:
        top = b["name"]["hits"]["hits"][0]["_source"].get("agent", {})
        last_seen_ms = b["last_seen"]["value"]
        is_active = last_seen_ms and (datetime.now(timezone.utc).timestamp() * 1000 - last_seen_ms) < 10 * 60 * 1000
        out.append({
            "agent_id": b["key"],
            "name": top.get("name", ""),
            "ip": top.get("ip", ""),
            "last_seen": b["last_seen"]["value_as_string"],
            "active": bool(is_active),
        })
    return web.json_response(out)


# ── AI Agents (crewai-soc) proxy - same rationale as the OpenSearch
# proxies above: the dashboard is static HTML with no server of its own,
# so this process makes the actual calls to crewai-soc/ollama (both only
# reachable by hostname on the docker network, not from a browser) and
# hands back JSON.
MISSION_MAP = {
    "investigate": ("full_soc", "/analyze/alert"),
    "triage": ("alert_triage", "/analyze/alert"),
    "hunt": ("threat_hunt", "/hunt"),
    "gaps": ("detection_gap", "/detection/gaps"),
}


async def handle_ai_health(request):
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(f"{CREWAI_URL}/health") as resp:
                data = await resp.json()
                return web.json_response(data)
    except Exception as e:
        return web.json_response({"status": "unreachable", "error": str(e)}, status=502)


async def handle_ai_ollama_model(request):
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(f"{OLLAMA_URL}/api/tags") as resp:
                data = await resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return web.json_response({"models": models})
    except Exception as e:
        return web.json_response({"models": [], "error": str(e)}, status=502)


async def handle_ai_jobs(request):
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(f"{CREWAI_URL}/jobs") as resp:
                data = await resp.json()
                return web.json_response(data)
    except Exception as e:
        return web.json_response({"total": 0, "jobs": [], "error": str(e)}, status=502)


async def handle_ai_job_detail(request):
    job_id = request.match_info["id"]
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(f"{CREWAI_URL}/jobs/{job_id}") as resp:
                data = await resp.json()
                return web.json_response(data, status=resp.status)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=502)


async def handle_ai_run(request):
    """Dispatches a real CrewAI mission - this actually invokes local Ollama
    inference (can take 30s-several minutes) and returns a job_id to poll,
    it does not fabricate a canned transcript."""
    body = await request.json()
    mission = body.get("mission")
    if mission not in MISSION_MAP:
        return web.json_response({"error": f"unknown mission '{mission}'"}, status=400)
    crew_mission, path = MISSION_MAP[mission]

    if path == "/hunt":
        payload = {
            "hypothesis": body.get("hypothesis") or "Lateral movement via SMB in the last 24h",
            "target_hosts": [],
            "time_window_hours": 24,
            "tactic_focus": "all",
        }
    elif path == "/detection/gaps":
        payload = {"tactic": body.get("tactic", "all"), "recent_incident": ""}
    else:
        payload = {
            "alert_type": body.get("alert_type", "manual_dashboard_trigger"),
            "source_ip": body.get("source_ip"),
            "hostname": body.get("hostname"),
            "severity": body.get("severity", "medium"),
            "mission": crew_mission,
        }

    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(f"{CREWAI_URL}{path}", json=payload) as resp:
                data = await resp.json()
                return web.json_response(data, status=resp.status)
    except Exception as e:
        return web.json_response({"error": f"crewai-soc unreachable: {e}"}, status=502)


# ── DFIR-IRIS proxy - same rationale: IRIS is only reachable by hostname
# on the docker network (https://dfir-iris:443, self-signed cert), and its
# API key stays server-side rather than shipping to every browser.
def _iris_headers():
    return {"Authorization": f"Bearer {IRIS_API_KEY}"}


async def handle_iris_cases(request):
    if not IRIS_API_KEY:
        return web.json_response({"error": "IRIS_API_KEY not configured", "cases": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{IRIS_URL}/manage/cases/filter", headers=_iris_headers(), ssl=False) as resp:
                data = await resp.json()
                cases = data.get("data", {}).get("cases", [])
                return web.json_response({"cases": cases})
    except Exception as e:
        return web.json_response({"error": str(e), "cases": []}, status=502)


async def handle_iris_case_iocs(request):
    cid = request.match_info["cid"]
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{IRIS_URL}/case/ioc/list", params={"cid": cid},
                                    headers=_iris_headers(), ssl=False) as resp:
                data = await resp.json()
                return web.json_response({"iocs": data.get("data", {}).get("ioc", [])})
    except Exception as e:
        return web.json_response({"error": str(e), "iocs": []}, status=502)


async def handle_iris_case_timeline(request):
    cid = request.match_info["cid"]
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{IRIS_URL}/case/timeline/events/list", params={"cid": cid},
                                    headers=_iris_headers(), ssl=False) as resp:
                data = await resp.json()
                return web.json_response({"timeline": data.get("data", {}).get("timeline", [])})
    except Exception as e:
        return web.json_response({"error": str(e), "timeline": []}, status=502)


# ── MISP proxy - same rationale: MISP is only reachable by hostname on
# the docker network, its port-80 vhost 301-redirects to https (which a
# browser or naive POST client can't follow correctly), and its API key
# stays server-side.
def _misp_headers():
    return {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}


async def handle_misp_search(request):
    value = request.query.get("value", "")
    if not MISP_KEY:
        return web.json_response({"error": "MISP_KEY not configured", "matches": []}, status=200)
    if not value:
        return web.json_response({"error": "missing ?value=", "matches": []}, status=400)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(f"{MISP_URL}/attributes/restSearch",
                                     json={"returnFormat": "json", "value": value, "limit": 20},
                                     headers=_misp_headers(), ssl=False) as resp:
                data = await resp.json()
                attrs = data.get("response", {}).get("Attribute", [])
                return web.json_response({
                    "value": value,
                    "matches": len(attrs),
                    "verdict": "MALICIOUS" if attrs else "NOT_FOUND",
                    "attributes": [{
                        "event_id": a.get("event_id"), "type": a.get("type"),
                        "value": a.get("value"), "category": a.get("category"),
                        "tags": [t.get("name") for t in a.get("Tag", [])],
                        "timestamp": a.get("timestamp"),
                    } for a in attrs],
                })
    except Exception as e:
        return web.json_response({"error": str(e), "matches": []}, status=502)


async def handle_misp_events(request):
    if not MISP_KEY:
        return web.json_response({"error": "MISP_KEY not configured", "events": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(f"{MISP_URL}/events/restSearch",
                                     json={"returnFormat": "json", "limit": 50},
                                     headers=_misp_headers(), ssl=False) as resp:
                data = await resp.json()
                events = [e.get("Event", e) for e in data.get("response", [])]
                return web.json_response({"events": events})
    except Exception as e:
        return web.json_response({"error": str(e), "events": []}, status=502)


async def handle_misp_feeds(request):
    if not MISP_KEY:
        return web.json_response({"error": "MISP_KEY not configured", "feeds": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{MISP_URL}/feeds/index",
                                    headers=_misp_headers(), ssl=False) as resp:
                data = await resp.json()
                feeds = [f.get("Feed", f) for f in data] if isinstance(data, list) else []
                return web.json_response({"feeds": feeds})
    except Exception as e:
        return web.json_response({"error": str(e), "feeds": []}, status=502)


# ── Unified services status strip - one endpoint the shared
# status-strip.js include on every dashboard polls, so "is X actually
# live" is answered the same way everywhere instead of N different ways.
def _recent_log_types(client, window="now-5m"):
    """Which log_type values have had at least one document in the
    window - the cheapest real signal that a sensor is actively shipping
    data (not just that its container is up)."""
    try:
        resp = client.search(index="soc-logs-*", body={
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": window}}},
            "aggs": {"types": {"terms": {"field": "log_type.keyword", "size": 20}}},
        })
        return {b["key"] for b in resp["aggregations"]["types"]["buckets"]}
    except Exception:
        return set()


async def _http_ping(session, url, method="get", **kwargs):
    try:
        async with session.request(method, url, ssl=False, timeout=ClientTimeout(total=4), **kwargs) as resp:
            return resp.status < 500
    except Exception:
        return False


async def handle_services_status(request):
    client = get_os_client()
    recent_types = _recent_log_types(client)

    async with ClientSession() as session:
        misp_ok, iris_ok, ai_ok, caldera_ok, ollama_ok = await asyncio.gather(
            _http_ping(session, f"{MISP_URL}/users/login"),
            _http_ping(session, f"{IRIS_URL}/"),
            _http_ping(session, f"{CREWAI_URL}/health"),
            _http_ping(session, f"{CALDERA_URL}/"),
            _http_ping(session, f"{OLLAMA_URL}/api/tags"),
        )

    try:
        os_health = client.cluster.health()
        os_ok = os_health.get("status") in ("green", "yellow")
    except Exception:
        os_ok = False

    services = [
        {"key": "opensearch", "name": "OpenSearch", "online": os_ok},
        {"key": "suricata", "name": "Suricata", "online": "suricata" in recent_types},
        {"key": "zeek", "name": "Zeek", "online": "zeek" in recent_types},
        {"key": "wazuh", "name": "Wazuh", "online": "wazuh" in recent_types},
        {"key": "misp", "name": "MISP", "online": misp_ok},
        {"key": "iris", "name": "DFIR-IRIS", "online": iris_ok},
        {"key": "ai_agents", "name": "AI Agents", "online": ai_ok},
        {"key": "ollama", "name": "Ollama", "online": ollama_ok},
        {"key": "caldera", "name": "Caldera", "online": caldera_ok},
    ]
    return web.json_response({"services": services})


async def handle_event_detail(request):
    """Fetch one full document by its OpenSearch _id, for click-to-drilldown."""
    doc_id = request.match_info["id"]
    client = get_os_client()
    resp = client.search(index="soc-logs-*", body={"query": {"ids": {"values": [doc_id]}}})
    hits = resp["hits"]["hits"]
    if not hits:
        return web.json_response({"error": "not found"}, status=404)
    h = hits[0]
    return web.json_response({"id": h["_id"], "index": h["_index"], **h["_source"]})


async def start_http_app():
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/api/suricata/feed", handle_suricata_feed)
    app.router.add_get("/api/suricata/summary", handle_suricata_summary)
    app.router.add_get("/api/suricata/categories", handle_suricata_categories)
    app.router.add_get("/api/suricata/timeline", handle_suricata_timeline)
    app.router.add_get("/api/suricata/top_signatures", handle_suricata_top_signatures)
    app.router.add_get("/api/zeek/summary", handle_zeek_summary)
    app.router.add_get("/api/zeek/conn_feed", handle_zeek_conn_feed)
    app.router.add_get("/api/zeek/protocol_mix", handle_zeek_protocol_mix)
    app.router.add_get("/api/zeek/dns_anomalies", handle_zeek_dns_anomalies)
    app.router.add_get("/api/zeek/llmnr", handle_zeek_llmnr)
    app.router.add_get("/api/wazuh/summary", handle_wazuh_summary)
    app.router.add_get("/api/wazuh/feed", handle_wazuh_feed)
    app.router.add_get("/api/wazuh/agents", handle_wazuh_agents)
    app.router.add_get("/api/ai/health", handle_ai_health)
    app.router.add_get("/api/ai/ollama_model", handle_ai_ollama_model)
    app.router.add_get("/api/ai/jobs", handle_ai_jobs)
    app.router.add_get("/api/ai/jobs/{id}", handle_ai_job_detail)
    app.router.add_post("/api/ai/run", handle_ai_run)
    app.router.add_get("/api/iris/cases", handle_iris_cases)
    app.router.add_get("/api/iris/case/{cid}/iocs", handle_iris_case_iocs)
    app.router.add_get("/api/iris/case/{cid}/timeline", handle_iris_case_timeline)
    app.router.add_get("/api/misp/search", handle_misp_search)
    app.router.add_get("/api/misp/events", handle_misp_events)
    app.router.add_get("/api/misp/feeds", handle_misp_feeds)
    app.router.add_get("/api/services/status", handle_services_status)
    app.router.add_get("/api/event/{id}", handle_event_detail)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, WS_HOST, HTTP_PORT)
    await site.start()
    log.info(f"HTTP API listening on {WS_HOST}:{HTTP_PORT}")


async def main():
    log.info(f"SOC WebSocket Streamer starting on {WS_HOST}:{WS_PORT}")
    log.info(f"OpenSearch: {OS_HOST}:{OS_PORT} | Poll interval: {POLL_SECS}s")

    async with websockets.serve(handler, WS_HOST, WS_PORT):
        await start_http_app()
        await asyncio.gather(
            poll_loop(),
            heartbeat_loop(),
        )


if __name__ == "__main__":
    asyncio.run(main())
