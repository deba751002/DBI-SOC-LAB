#!/usr/bin/env python3
"""
Wazuh Remote Connector — pulls new alerts from an externally-hosted Wazuh
indexer (e.g. an AWS EC2 deployment) and forwards them into this lab's
Vector pipeline, so they land in the same soc-logs-* OpenSearch index as
every other source.

Why polling instead of a push from the remote side: most remote Wazuh
deployments (correctly) only expose the dashboard (443) to the internet and
keep the indexer/manager internal for security. Polling only requires this
lab to make outbound HTTPS requests to the indexer's _search API — it does
not require the remote side to reach back into this lab's network.

Requires: the remote indexer's port (default 9200) reachable from this lab
(e.g. an AWS security group rule scoped to this lab's public IP only), plus
indexer credentials with read access to the wazuh-alerts-* index.

NOTE ON INDEX/FIELD NAMES: this script assumes the standard Wazuh index
pattern (wazuh-alerts-*) and timestamp field (timestamp) used since Wazuh 4.x.
Confirm both against your actual deployment (Wazuh Dashboard -> Stack
Management -> Index Patterns, or Discover) before relying on this — if they
differ, override with WAZUH_ALERT_INDEX / WAZUH_TIMESTAMP_FIELD below.
"""
import os
import time
import logging
import requests

WAZUH_INDEXER_URL      = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER     = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
WAZUH_ALERT_INDEX      = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")
WAZUH_TIMESTAMP_FIELD  = os.getenv("WAZUH_TIMESTAMP_FIELD", "timestamp")
VERIFY_TLS             = os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").lower() == "true"
POLL_INTERVAL_SECS     = int(os.getenv("POLL_INTERVAL_SECS", "30"))
PAGE_SIZE              = int(os.getenv("WAZUH_POLL_PAGE_SIZE", "500"))
VECTOR_URL             = os.getenv("VECTOR_URL", "http://vector:6006")
STATE_FILE             = os.getenv("STATE_FILE", "/data/last_poll_ts.txt")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [WAZUH-REMOTE] %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def load_last_ts() -> str:
    try:
        with open(STATE_FILE, "r") as f:
            ts = f.read().strip()
            if ts:
                return ts
    except FileNotFoundError:
        pass
    # First run: start from "now" so we don't backfill the remote's entire
    # alert history on first start.
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def save_last_ts(ts: str) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(ts)


def poll_once(last_ts: str):
    query = {
        "query": {"range": {WAZUH_TIMESTAMP_FIELD: {"gt": last_ts}}},
        "sort": [{WAZUH_TIMESTAMP_FIELD: "asc"}],
        "size": PAGE_SIZE,
    }
    resp = requests.post(
        f"{WAZUH_INDEXER_URL}/{WAZUH_ALERT_INDEX}/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=VERIFY_TLS,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])


def forward_to_vector(source_doc: dict) -> bool:
    payload = dict(source_doc)
    payload["log_source"] = "endpoint"
    payload["log_type"] = "wazuh-remote"
    try:
        r = requests.post(VECTOR_URL, json=payload, timeout=5)
        return r.status_code < 400
    except requests.RequestException as e:
        log.warning("forward to Vector failed: %s", e)
        return False


def main():
    if not WAZUH_INDEXER_URL:
        raise SystemExit("WAZUH_INDEXER_URL is required, e.g. https://siem.dbi360.com:9200")

    last_ts = load_last_ts()
    log.info("Starting, indexer=%s index=%s resuming_from=%s", WAZUH_INDEXER_URL, WAZUH_ALERT_INDEX, last_ts)

    while True:
        try:
            hits = poll_once(last_ts)
            forwarded = 0
            for hit in hits:
                doc = hit.get("_source", {})
                if forward_to_vector(doc):
                    forwarded += 1
                ts = doc.get(WAZUH_TIMESTAMP_FIELD)
                if ts:
                    last_ts = ts
            if hits:
                save_last_ts(last_ts)
                log.info("Polled %d alert(s), forwarded %d, last_ts=%s", len(hits), forwarded, last_ts)
        except requests.RequestException as e:
            log.error("Poll cycle failed (network/auth): %s", e)
        except Exception as e:
            log.error("Poll cycle failed: %s", e)

        time.sleep(POLL_INTERVAL_SECS)


if __name__ == "__main__":
    main()
