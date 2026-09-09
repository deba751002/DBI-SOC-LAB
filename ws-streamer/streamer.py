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
from aiohttp import web

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
            "sigs": {"cardinality": {"field": "rule.id.keyword"}},
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
            "terms": {"field": "rule.id.keyword", "size": 10, "order": {"_count": "desc"}},
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
