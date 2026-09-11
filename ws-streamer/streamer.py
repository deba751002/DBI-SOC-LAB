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
CALDERA_API_KEY = os.getenv("CALDERA_API_KEY", "")
VELOCIRAPTOR_API_CLIENT_CONFIG = os.getenv("VELOCIRAPTOR_API_CLIENT_CONFIG", "/app/velociraptor_api_client.config.yaml")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "")
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://thehive:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
CORTEX_URL = os.getenv("CORTEX_URL", "http://cortex:9001")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")
NETBOX_URL = os.getenv("NETBOX_URL", "http://netbox:8080")
NETBOX_API_TOKEN = os.getenv("NETBOX_API_TOKEN", "")
N8N_URL = os.getenv("N8N_URL", "http://n8n:5678")
N8N_API_KEY = os.getenv("N8N_API_KEY", "")
VAULT_URL = os.getenv("VAULT_URL", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_WS_STREAMER_TOKEN", "")

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
    # POST/DELETE endpoints (AI mission launch, Velociraptor VQL, Caldera
    # operation create) were silently broken in real browsers - curl doesn't
    # enforce CORS so this never showed up in API testing, only once a
    # dashboard's own fetch() hit a real preflight check.
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
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


# ── Caldera proxy - same rationale: `caldera` only resolves on the
# docker network, and its API key stays server-side instead of shipping
# to the browser.
def _caldera_headers():
    return {"KEY": CALDERA_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}


async def handle_caldera_adversaries(request):
    if not CALDERA_API_KEY:
        return web.json_response({"error": "CALDERA_API_KEY not configured", "adversaries": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{CALDERA_URL}/api/v2/adversaries",
                                    headers=_caldera_headers(), ssl=False) as resp:
                data = await resp.json(content_type=None)
                return web.json_response({"adversaries": data})
    except Exception as e:
        return web.json_response({"error": str(e), "adversaries": []}, status=502)


async def handle_caldera_agents(request):
    if not CALDERA_API_KEY:
        return web.json_response({"error": "CALDERA_API_KEY not configured", "agents": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{CALDERA_URL}/api/v2/agents",
                                    headers=_caldera_headers(), ssl=False) as resp:
                data = await resp.json(content_type=None)
                return web.json_response({"agents": data})
    except Exception as e:
        return web.json_response({"error": str(e), "agents": []}, status=502)


async def handle_caldera_operations(request):
    if not CALDERA_API_KEY:
        return web.json_response({"error": "CALDERA_API_KEY not configured", "operations": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{CALDERA_URL}/api/v2/operations",
                                    headers=_caldera_headers(), ssl=False) as resp:
                data = await resp.json(content_type=None)
                ops = [{
                    "id": o.get("id"), "name": o.get("name"), "state": o.get("state"),
                    "start": o.get("start"), "finish": o.get("finish"),
                    "adversary": (o.get("adversary") or {}).get("name"),
                    "group": o.get("group"),
                } for o in data]
                return web.json_response({"operations": ops})
    except Exception as e:
        return web.json_response({"error": str(e), "operations": []}, status=502)


async def handle_caldera_create_operation(request):
    # This Caldera build's /api/v2/operations route only registers GET/DELETE -
    # creation only exists on the legacy dispatcher at PUT /api/rest with
    # index="operations" and a flat adversary_id (confirmed by reading
    # rest_svc.py's _build_operation_object inside the running container).
    if not CALDERA_API_KEY:
        return web.json_response({"error": "CALDERA_API_KEY not configured"}, status=200)
    try:
        body = await request.json()
        adversary_id = body.get("adversary_id")
        name = body.get("name", "SOC Lab Operation")
        group = body.get("group", "red")
        if not adversary_id:
            return web.json_response({"error": "missing adversary_id"}, status=400)
        payload = {
            "index": "operations",
            "name": name,
            "adversary_id": adversary_id,
            "group": group,
            "state": "running",
            "auto_close": "0",
            "obfuscator": "plain-text",
        }
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.put(f"{CALDERA_URL}/api/rest",
                                    json=payload, headers=_caldera_headers(), ssl=False) as resp:
                data = await resp.json(content_type=None)
                op = data[0] if isinstance(data, list) and data else {}
                return web.json_response({
                    "id": op.get("id"), "name": op.get("name"), "state": op.get("state"),
                    "adversary": (op.get("adversary") or {}).get("name"),
                }, status=resp.status)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=502)


async def handle_caldera_operation_links(request):
    # There is no standalone /operations/{id}/links route in this Caldera
    # build (operation_api.py only registers get/get_by_id/delete/report) -
    # executed steps live in the "chain" field of the full operation object.
    op_id = request.match_info["op_id"]
    if not CALDERA_API_KEY:
        return web.json_response({"error": "CALDERA_API_KEY not configured", "links": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{CALDERA_URL}/api/v2/operations/{op_id}",
                                    headers=_caldera_headers(), ssl=False) as resp:
                data = await resp.json(content_type=None)
                chain = data.get("chain", []) if isinstance(data, dict) else []
                links = [{
                    "id": l.get("id") or l.get("unique"),
                    "ability_id": (l.get("ability") or {}).get("ability_id"),
                    "name": (l.get("ability") or {}).get("name"),
                    "tactic": (l.get("ability") or {}).get("tactic"),
                    "technique_id": (l.get("ability") or {}).get("technique_id"),
                    "status": l.get("status"),
                    "finish": l.get("finish"),
                } for l in chain]
                return web.json_response({"links": links})
    except Exception as e:
        return web.json_response({"error": str(e), "links": []}, status=502)


# ── Velociraptor proxy - unlike everything else here this is not a REST
# API, it's gRPC + mTLS. We authenticate with a cert/key bundle generated
# once via `velociraptor config api_client` on the server (kept outside the
# repo - it embeds a private key) and run VQL queries through it. grpc's
# Python client is synchronous, so each call is pushed to a thread so it
# doesn't block the event loop.
_velo_channel = None
_velo_stub = None


def _get_velo_stub():
    global _velo_channel, _velo_stub
    if _velo_stub is not None:
        return _velo_stub
    import grpc
    from pyvelociraptor import LoadConfigFile
    from pyvelociraptor import api_pb2_grpc
    config = LoadConfigFile(VELOCIRAPTOR_API_CLIENT_CONFIG)
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    # api_connection_string in the generated config is host-agnostic
    # (0.0.0.0:8001) - always dial the real service name on the docker
    # network. The server's cert is issued for "VelociraptorServer", not
    # for that hostname, so grpc's TLS hostname check needs an override.
    _velo_channel = grpc.secure_channel(
        "velociraptor:8001", creds,
        options=(("grpc.ssl_target_name_override", "VelociraptorServer"),),
    )
    _velo_stub = api_pb2_grpc.APIStub(_velo_channel)
    return _velo_stub


def _velo_query_sync(vql: str, max_wait: int = 5) -> list[dict]:
    from pyvelociraptor import api_pb2
    stub = _get_velo_stub()
    request = api_pb2.VQLCollectorArgs(max_wait=max_wait, Query=[api_pb2.VQLRequest(VQL=vql)])
    rows = []
    for response in stub.Query(request):
        if response.Response:
            rows.extend(json.loads(response.Response))
    return rows


async def _velo_query(vql: str, max_wait: int = 5) -> list[dict]:
    return await asyncio.to_thread(_velo_query_sync, vql, max_wait)


async def handle_velo_clients(request):
    try:
        rows = await _velo_query(
            "SELECT client_id, os_info.hostname AS hostname, os_info.system AS platform, "
            "last_seen_at, first_seen_at FROM clients() LIMIT 100"
        )
        return web.json_response({"clients": rows})
    except Exception as e:
        return web.json_response({"error": str(e), "clients": []}, status=502)


async def handle_velo_hunts(request):
    try:
        rows = await _velo_query(
            "SELECT hunt_id, hunt_description AS description, state, create_time, "
            "start_request.artifacts AS artifacts, stats.total_clients_scheduled AS scheduled, "
            "stats.total_clients_with_results AS with_results "
            "FROM hunts() ORDER BY create_time DESC LIMIT 50"
        )
        return web.json_response({"hunts": rows})
    except Exception as e:
        return web.json_response({"error": str(e), "hunts": []}, status=502)


async def handle_velo_query(request):
    body = await request.json()
    vql = body.get("vql", "")
    if not vql:
        return web.json_response({"error": "missing vql"}, status=400)
    try:
        rows = await _velo_query(vql, max_wait=int(body.get("max_wait", 10)))
        return web.json_response({"rows": rows})
    except Exception as e:
        return web.json_response({"error": str(e), "rows": []}, status=502)


# ── Keycloak proxy - authenticates once with the admin-cli password grant
# (Keycloak's access tokens are short-lived, ~60s, so we cache and refetch
# rather than re-authenticate on every dashboard poll).
_keycloak_token: str | None = None
_keycloak_token_expiry: float = 0.0


async def _keycloak_admin_token(session) -> str:
    global _keycloak_token, _keycloak_token_expiry
    now = asyncio.get_event_loop().time()
    if _keycloak_token and now < _keycloak_token_expiry:
        return _keycloak_token
    async with session.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={"client_id": "admin-cli", "username": KEYCLOAK_ADMIN_USER,
              "password": KEYCLOAK_ADMIN_PASSWORD, "grant_type": "password"},
    ) as resp:
        data = await resp.json(content_type=None)
        if "access_token" not in data:
            raise RuntimeError(data.get("error_description", "Keycloak auth failed"))
        _keycloak_token = data["access_token"]
        _keycloak_token_expiry = now + int(data.get("expires_in", 60)) - 10
        return _keycloak_token


async def handle_keycloak_realms(request):
    if not KEYCLOAK_ADMIN_PASSWORD:
        return web.json_response({"error": "KEYCLOAK_ADMIN_PASSWORD not configured", "realms": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            token = await _keycloak_admin_token(session)
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{KEYCLOAK_URL}/admin/realms", headers=headers) as resp:
                realms = await resp.json(content_type=None)

            result = []
            for r in realms:
                name = r["realm"]
                async with session.get(f"{KEYCLOAK_URL}/admin/realms/{name}/users/count", headers=headers) as resp:
                    user_count = await resp.json(content_type=None)
                async with session.get(f"{KEYCLOAK_URL}/admin/realms/{name}/clients", headers=headers) as resp:
                    clients = await resp.json(content_type=None)
                result.append({
                    "realm": name, "enabled": r.get("enabled"),
                    "user_count": user_count, "client_count": len(clients),
                })
            return web.json_response({"realms": result})
    except Exception as e:
        return web.json_response({"error": str(e), "realms": []}, status=502)


async def handle_keycloak_users(request):
    realm = request.query.get("realm", "master")
    if not KEYCLOAK_ADMIN_PASSWORD:
        return web.json_response({"error": "KEYCLOAK_ADMIN_PASSWORD not configured", "users": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            token = await _keycloak_admin_token(session)
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{KEYCLOAK_URL}/admin/realms/{realm}/users", headers=headers) as resp:
                users = await resp.json(content_type=None)
                result = [{
                    "id": u.get("id"), "username": u.get("username"), "email": u.get("email"),
                    "enabled": u.get("enabled"), "created": u.get("createdTimestamp"),
                } for u in users]
                return web.json_response({"users": result})
    except Exception as e:
        return web.json_response({"error": str(e), "users": []}, status=502)


async def handle_keycloak_events(request):
    # Login-event logging is off by default in Keycloak - an empty list here
    # is an honest "not enabled yet", not a proxy failure.
    realm = request.query.get("realm", "master")
    if not KEYCLOAK_ADMIN_PASSWORD:
        return web.json_response({"error": "KEYCLOAK_ADMIN_PASSWORD not configured", "events": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            token = await _keycloak_admin_token(session)
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get(f"{KEYCLOAK_URL}/admin/realms/{realm}/events?max=50", headers=headers) as resp:
                events = await resp.json(content_type=None)
                return web.json_response({"events": events if isinstance(events, list) else []})
    except Exception as e:
        return web.json_response({"error": str(e), "events": []}, status=502)


# ── TheHive + Cortex proxy
def _thehive_headers():
    return {"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"}


def _cortex_headers():
    # No Content-Type here - Cortex's Play backend tries to parse the (empty)
    # body as JSON on a plain GET if this header is present and errors out.
    return {"Authorization": f"Bearer {CORTEX_API_KEY}"}


async def handle_thehive_cases(request):
    if not THEHIVE_API_KEY:
        return web.json_response({"error": "THEHIVE_API_KEY not configured", "cases": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(
                f"{THEHIVE_URL}/api/v1/query",
                json={"query": [{"_name": "listCase"}, {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                                {"_name": "page", "from": 0, "to": 50}]},
                headers=_thehive_headers(),
            ) as resp:
                cases = await resp.json(content_type=None)
                if not isinstance(cases, list):
                    return web.json_response({"error": str(cases), "cases": []}, status=502)
                return web.json_response({"cases": cases})
    except Exception as e:
        return web.json_response({"error": str(e), "cases": []}, status=502)


async def handle_thehive_alerts(request):
    if not THEHIVE_API_KEY:
        return web.json_response({"error": "THEHIVE_API_KEY not configured", "alerts": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(
                f"{THEHIVE_URL}/api/v1/query",
                json={"query": [{"_name": "listAlert"}, {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                                {"_name": "page", "from": 0, "to": 50}]},
                headers=_thehive_headers(),
            ) as resp:
                alerts = await resp.json(content_type=None)
                if not isinstance(alerts, list):
                    return web.json_response({"error": str(alerts), "alerts": []}, status=502)
                return web.json_response({"alerts": alerts})
    except Exception as e:
        return web.json_response({"error": str(e), "alerts": []}, status=502)


async def handle_cortex_analyzers(request):
    if not CORTEX_API_KEY:
        return web.json_response({"error": "CORTEX_API_KEY not configured", "analyzers": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{CORTEX_URL}/api/analyzer", headers=_cortex_headers()) as resp:
                data = await resp.json(content_type=None)
                if not isinstance(data, list):
                    return web.json_response({"error": str(data), "analyzers": []}, status=502)
                analyzers = [{"id": a.get("id"), "name": a.get("name"), "version": a.get("version")} for a in data]
                return web.json_response({"analyzers": analyzers})
    except Exception as e:
        return web.json_response({"error": str(e), "analyzers": []}, status=502)


async def handle_cortex_jobs(request):
    if not CORTEX_API_KEY:
        return web.json_response({"error": "CORTEX_API_KEY not configured", "jobs": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.post(
                f"{CORTEX_URL}/api/job/_search?range=0-50&sort=-createdAt",
                json={"query": {"_and": []}}, headers=_cortex_headers(),
            ) as resp:
                data = await resp.json(content_type=None)
                if not isinstance(data, list):
                    return web.json_response({"error": str(data), "jobs": []}, status=502)
                jobs = [{
                    "id": j.get("id"), "analyzer": j.get("analyzerName"), "status": j.get("status"),
                    "observable": j.get("data") or j.get("dataType"), "date": j.get("createdAt"),
                } for j in data]
                return web.json_response({"jobs": jobs})
    except Exception as e:
        return web.json_response({"error": str(e), "jobs": []}, status=502)


# ── NetBox proxy
def _netbox_headers():
    return {"Authorization": f"Token {NETBOX_API_TOKEN}"}


async def handle_netbox_devices(request):
    if not NETBOX_API_TOKEN:
        return web.json_response({"error": "NETBOX_API_TOKEN not configured", "devices": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{NETBOX_URL}/api/dcim/devices/?limit=100", headers=_netbox_headers()) as resp:
                data = await resp.json(content_type=None)
                results = data.get("results", []) if isinstance(data, dict) else []
                devices = [{
                    "id": d.get("id"), "name": d.get("name"),
                    "role": (d.get("device_role") or d.get("role") or {}).get("name"),
                    "site": (d.get("site") or {}).get("name"),
                    "status": (d.get("status") or {}).get("label"),
                    "primary_ip": (d.get("primary_ip") or {}).get("address"),
                } for d in results]
                return web.json_response({"devices": devices, "count": data.get("count", len(devices)) if isinstance(data, dict) else len(devices)})
    except Exception as e:
        return web.json_response({"error": str(e), "devices": []}, status=502)


async def handle_netbox_ips(request):
    if not NETBOX_API_TOKEN:
        return web.json_response({"error": "NETBOX_API_TOKEN not configured", "ips": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{NETBOX_URL}/api/ipam/ip-addresses/?limit=100", headers=_netbox_headers()) as resp:
                data = await resp.json(content_type=None)
                results = data.get("results", []) if isinstance(data, dict) else []
                ips = [{
                    "address": ip.get("address"), "status": (ip.get("status") or {}).get("label"),
                    "assigned_to": (ip.get("assigned_object") or {}).get("device", {}).get("name")
                    if ip.get("assigned_object") else None,
                } for ip in results]
                return web.json_response({"ips": ips, "count": data.get("count", len(ips)) if isinstance(data, dict) else len(ips)})
    except Exception as e:
        return web.json_response({"error": str(e), "ips": []}, status=502)


async def handle_netbox_sites(request):
    if not NETBOX_API_TOKEN:
        return web.json_response({"error": "NETBOX_API_TOKEN not configured", "sites": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{NETBOX_URL}/api/dcim/sites/?limit=100", headers=_netbox_headers()) as resp:
                data = await resp.json(content_type=None)
                results = data.get("results", []) if isinstance(data, dict) else []
                sites = [{"id": s.get("id"), "name": s.get("name"), "status": (s.get("status") or {}).get("label")} for s in results]
                return web.json_response({"sites": sites})
    except Exception as e:
        return web.json_response({"error": str(e), "sites": []}, status=502)


# ── n8n proxy
def _n8n_headers():
    return {"X-N8N-API-KEY": N8N_API_KEY}


async def handle_n8n_workflows(request):
    if not N8N_API_KEY:
        return web.json_response({"error": "N8N_API_KEY not configured", "workflows": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{N8N_URL}/api/v1/workflows", headers=_n8n_headers()) as resp:
                data = await resp.json(content_type=None)
                results = data.get("data", []) if isinstance(data, dict) else []
                workflows = [{
                    "id": w.get("id"), "name": w.get("name"), "active": w.get("active"),
                    "updated": w.get("updatedAt"), "nodes": len(w.get("nodes", [])),
                } for w in results]
                return web.json_response({"workflows": workflows})
    except Exception as e:
        return web.json_response({"error": str(e), "workflows": []}, status=502)


async def handle_n8n_executions(request):
    if not N8N_API_KEY:
        return web.json_response({"error": "N8N_API_KEY not configured", "executions": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{N8N_URL}/api/v1/executions?limit=50", headers=_n8n_headers()) as resp:
                data = await resp.json(content_type=None)
                results = data.get("data", []) if isinstance(data, dict) else []
                executions = [{
                    "id": e.get("id"), "workflow_id": e.get("workflowId"), "status": e.get("status"),
                    "started": e.get("startedAt"), "finished": e.get("stoppedAt"),
                } for e in results]
                return web.json_response({"executions": executions})
    except Exception as e:
        return web.json_response({"error": str(e), "executions": []}, status=502)


# ── Vault proxy - deliberately never returns secret VALUES to the browser,
# only paths/metadata (created time, version). A dashboard that displays
# the very secrets Vault exists to protect would defeat the point of it.
def _vault_headers():
    return {"X-Vault-Token": VAULT_TOKEN}


async def handle_vault_status(request):
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{VAULT_URL}/v1/sys/health") as resp:
                data = await resp.json(content_type=None)
                return web.json_response({
                    "initialized": data.get("initialized"),
                    "sealed": data.get("sealed"),
                    "version": data.get("version"),
                })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=502)


async def handle_vault_secrets(request):
    if not VAULT_TOKEN:
        return web.json_response({"error": "VAULT_WS_STREAMER_TOKEN not configured", "secrets": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{VAULT_URL}/v1/secret/metadata/soc-lab?list=true", headers=_vault_headers()) as resp:
                if resp.status == 404:
                    return web.json_response({"secrets": []})
                data = await resp.json(content_type=None)
                keys = data.get("data", {}).get("keys", [])

            secrets = []
            for key in keys:
                async with session.get(f"{VAULT_URL}/v1/secret/metadata/soc-lab/{key}", headers=_vault_headers()) as resp:
                    meta = await resp.json(content_type=None)
                    versions = meta.get("data", {}).get("versions", {})
                    current = meta.get("data", {}).get("current_version")
                    latest = versions.get(str(current), {}) if current else {}
                    secrets.append({
                        "path": f"secret/soc-lab/{key}",
                        "version": current,
                        "created": latest.get("created_time"),
                    })
            return web.json_response({"secrets": secrets})
    except Exception as e:
        return web.json_response({"error": str(e), "secrets": []}, status=502)


async def handle_vault_mounts(request):
    if not VAULT_TOKEN:
        return web.json_response({"error": "VAULT_WS_STREAMER_TOKEN not configured", "mounts": []}, status=200)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(f"{VAULT_URL}/v1/sys/mounts", headers=_vault_headers()) as resp:
                data = await resp.json(content_type=None)
                mounts = data.get("data", {})
                result = [{"path": path, "type": m.get("type")} for path, m in mounts.items()
                          if not path.startswith(("sys/", "identity/", "cubbyhole/"))]
                return web.json_response({"mounts": result})
    except Exception as e:
        return web.json_response({"error": str(e), "mounts": []}, status=502)


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
        misp_ok, iris_ok, ai_ok, caldera_ok, ollama_ok, velo_ok, st2_ok, keycloak_ok, thehive_ok, cortex_ok, netbox_ok, n8n_ok, vault_ok = await asyncio.gather(
            _http_ping(session, f"{MISP_URL}/users/login"),
            _http_ping(session, f"{IRIS_URL}/"),
            _http_ping(session, f"{CREWAI_URL}/health"),
            _http_ping(session, f"{CALDERA_URL}/"),
            _http_ping(session, f"{OLLAMA_URL}/api/tags"),
            _http_ping(session, "https://velociraptor:8889/"),
            _http_ping(session, "http://st2web/"),
            _http_ping(session, f"{KEYCLOAK_URL}/realms/master"),
            _http_ping(session, f"{THEHIVE_URL}/api/status"),
            _http_ping(session, f"{CORTEX_URL}/api/status"),
            _http_ping(session, f"{NETBOX_URL}/api/"),
            _http_ping(session, f"{N8N_URL}/"),
            _http_ping(session, f"{VAULT_URL}/v1/sys/health"),
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
        {"key": "velociraptor", "name": "Velociraptor", "online": velo_ok},
        {"key": "stackstorm", "name": "StackStorm", "online": st2_ok},
        {"key": "keycloak", "name": "Keycloak", "online": keycloak_ok},
        {"key": "thehive", "name": "TheHive", "online": thehive_ok},
        {"key": "cortex", "name": "Cortex", "online": cortex_ok},
        {"key": "netbox", "name": "NetBox", "online": netbox_ok},
        {"key": "n8n", "name": "n8n", "online": n8n_ok},
        {"key": "vault", "name": "Vault", "online": vault_ok},
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
    app.router.add_get("/api/caldera/adversaries", handle_caldera_adversaries)
    app.router.add_get("/api/caldera/agents", handle_caldera_agents)
    app.router.add_get("/api/caldera/operations", handle_caldera_operations)
    app.router.add_post("/api/caldera/operations", handle_caldera_create_operation)
    app.router.add_get("/api/caldera/operations/{op_id}/links", handle_caldera_operation_links)
    app.router.add_get("/api/velociraptor/clients", handle_velo_clients)
    app.router.add_get("/api/velociraptor/hunts", handle_velo_hunts)
    app.router.add_post("/api/velociraptor/query", handle_velo_query)
    app.router.add_get("/api/keycloak/realms", handle_keycloak_realms)
    app.router.add_get("/api/keycloak/users", handle_keycloak_users)
    app.router.add_get("/api/keycloak/events", handle_keycloak_events)
    app.router.add_get("/api/thehive/cases", handle_thehive_cases)
    app.router.add_get("/api/thehive/alerts", handle_thehive_alerts)
    app.router.add_get("/api/cortex/analyzers", handle_cortex_analyzers)
    app.router.add_get("/api/cortex/jobs", handle_cortex_jobs)
    app.router.add_get("/api/netbox/devices", handle_netbox_devices)
    app.router.add_get("/api/netbox/ips", handle_netbox_ips)
    app.router.add_get("/api/netbox/sites", handle_netbox_sites)
    app.router.add_get("/api/n8n/workflows", handle_n8n_workflows)
    app.router.add_get("/api/n8n/executions", handle_n8n_executions)
    app.router.add_get("/api/vault/status", handle_vault_status)
    app.router.add_get("/api/vault/secrets", handle_vault_secrets)
    app.router.add_get("/api/vault/mounts", handle_vault_mounts)
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
