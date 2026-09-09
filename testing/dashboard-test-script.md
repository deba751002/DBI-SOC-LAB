# DBI SOC Dashboard — Live Data Test Script

Base URL: `http://192.168.30.206`
API base (ws-streamer): `http://192.168.30.206:8766`

Goal: confirm three dashboards show REAL live data (not hardcoded/fake), and
that click-to-drilldown works. Report PASS/FAIL for each numbered check below,
with a screenshot or the actual value seen where it says "record value".

---

## 0. Pre-check: API is reachable directly

Open these URLs directly in the browser (should return JSON, not an error page):

1. `http://192.168.30.206:8766/api/zeek/summary`
2. `http://192.168.30.206:8766/api/wazuh/summary`
3. `http://192.168.30.206:8766/api/suricata/summary`

PASS = each returns a JSON object with numeric fields (e.g. `{"connections_1h": 1234, ...}`).
FAIL = connection refused / timeout / HTML error page → report the exact error.

---

## 1. Zeek Network dashboard — `http://192.168.30.206/03_zeek_network.html`

1. **KPIs load with real numbers** (not stuck on "—"): Connections, Notices, DNS
   Queries, LLMNR/NBT-NS should all show numbers within ~2 seconds of page load.
   Record the four values.
2. **conn.log — Live Stream panel** shows real-looking lines with actual local
   IPs (e.g. `192.168.30.x` / `192.168.31.x`), NOT `10.0.0.x` addresses (that
   subnet would indicate leftover fake data).
3. **Click any line in the conn.log stream.** A modal titled "Event Detail"
   should open showing a table of raw fields (timestamp, id.orig_h, id.orig_p,
   proto, conn_state, etc.). Close it with the × button.
4. **Protocol Mix chart** renders horizontal bars with real protocol/service
   labels (e.g. `dns`, `other`, `ssl`) — not the old fixed set
   `HTTP/HTTPS/DNS/SMB/SSH/LLMNR/RDP/FTP` with numbers `1240,1890,621...`.
5. **DNS Anomalies table**: either shows real flagged rows, or the text
   "No anomalies flagged in the last hour." Should NOT show the old fixed
   rows (`aGVsbG8ud29ybGQ.evil.io`, `c2.coba1t.ru`, etc.).
6. **LLMNR / NBT-NS Query Volume table**: rows should show real querier IPs
   and a destination that is a multicast/broadcast address (`224.0.0.252`,
   `ff02::1:3`, or an `x.x.x.255` broadcast) — NOT the old fixed
   `10.0.0.42 / 192.168.1.105 / FILESERVER` style rows. Clicking a row should
   open the same Event Detail modal.
7. **Reload the page after 15+ seconds** and confirm the KPI numbers changed
   (proof it's live-refreshing every 10s, not a one-time static render).

---

## 2. Suricata IDS dashboard — `http://192.168.30.206/04_suricata_ids.html`

1. **KPIs**: Blocked (IPS), Alerts (24h), Unique Signatures (24h), Distinct
   Source IPs (24h) — all populate with numbers. Blocked (IPS) will likely be
   `0` (this lab runs passive IDS mode, not inline IPS) — that is CORRECT
   behavior, not a bug.
2. **Live EVE JSON Alert Feed**: shows real rows with real signature names
   (ET rules) and real source IPs — not the fixed 7-alert loop
   (`Cobalt Strike Beacon`, `10.0.1.50`, etc. repeating every 7s).
3. **Click any row in the live feed.** Event Detail modal opens with the full
   raw Suricata alert JSON (look for `alert.signature`, `alert.category`,
   `src_ip`, `dest_ip`, `proto`).
4. **Alert Categories chart**: bars reflect real category names/counts from
   the last 24h, not the fixed `Malware/Scan/Exploit/Policy/Trojan/Credential/DNS`
   with values `412,834,120,234,89,45,100`.
5. **30-min Alert Timeline chart**: bars should look like plausible real
   traffic (can be mostly zero on a quiet network) — NOT random noise between
   10-90 changing every reload (that was the old `Math.random()` fake).
6. **Top Signatures (24h) table**: real SIDs/signatures/counts, or
   "No Suricata alerts in the last 24h." Click a row → Event Detail modal opens.

---

## 3. Wazuh EDR dashboard — `http://192.168.30.206/13_wazuh_edr.html`

1. **Topbar** shows "Manager healthy · N agents active" where N is a real
   number (currently should be 2 or 3 — one Linux + one Windows test agent,
   possibly the manager itself).
2. **KPIs**: Agents Active, Critical Alerts (24h), Total Alerts (24h), FIM
   Events (24h). FIM Events should currently show `0` with sub-text
   "syscheck disabled — see File Integrity tab" — that is CORRECT (FIM isn't
   enabled yet in this lab), not a bug.
3. **Recent Wazuh Alerts table**: real rows with real agent hostnames
   (should include `BBSR-LAP-TEST1` or `ubuntu-soc-server`), NOT the fixed
   `WIN-DC01 / WKSTN-FINANCE-01 / SRV-FILESERVER-01 / my-laptop` roster.
4. **Click any alert row.** Event Detail modal opens showing the full raw
   Wazuh alert (rule.description, rule.level, agent.name, decoder.name, etc.)
5. **Agent Status panel**: shows the real enrolled agent(s) with a green dot
   if active in the last 10 minutes, red dot if stale, and a real
   "last seen Xm ago" — NOT the fixed 6-agent list
   (`WIN-DC01, WKSTN-FINANCE-01, WKSTN-LEGAL-05, SRV-HR-02, SRV-FILESERVER-01, my-laptop`
   all marked "active").

---

## 4. Failure modes to watch for (and how to read them)

- Any panel showing **"Could not reach ws-streamer API"** or a blank
  chart/table with no error text → likely means port 8766 isn't reachable
  from the browser's network, or a CORS/JS console error. Open browser
  DevTools → Console/Network tab and capture the actual error for the
  `/api/...` request that failed.
- A KPI stuck permanently on **"—"** → same as above, API call failing
  silently (caught in a try/catch that leaves the placeholder).
- Numbers that look suspiciously "too clean" (e.g. exactly `1,834`,
  `38,412`, `2.4 Gbps`) or IPs starting with `10.0.0.x` / `10.0.1.x` /
  `10.0.3.x` / `45.132.227.89` / `185.220.101.45` → these are the OLD
  hardcoded fake values; if seen, the browser likely loaded a cached/old
  version of the page — hard-refresh (Ctrl+Shift+R) and retry.

---

## 5. Report format

For each of the ~20 checks above, report: **PASS** / **FAIL** / **N/A**, plus
for FAILs: the exact error message, browser console output, or screenshot.
