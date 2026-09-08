# Wazuh Agent — Endpoint Deployment

Host-based EDR: log collection, active response, and its own CVE vulnerability
detector. This lab's own File Integrity Monitoring watcher is used instead of
Wazuh's built-in FIM (syscheck) — see `endpoint-configs/windows/fim/` — so
there's no duplicate file-change alerting between the two.

## Firewall / port impact — read this first

**No new inbound port is opened on the endpoint.** The Wazuh agent is a
push-only client: it connects *out* to the manager, the same way a browser
connects out to a website. Nothing on the endpoint listens for incoming
connections.

| Port | Direction | Purpose |
|---|---|---|
| TCP 1514 | Agent → Manager (outbound) | Ongoing log/event data |
| TCP 1515 | Agent → Manager (outbound) | One-time enrollment on first install |

If your endpoint already has another management agent listening on its own
ports (an RMM tool, an out-of-band management engine, etc.), Wazuh doesn't
touch those ports and doesn't need them — it only needs *outbound* 1514/1515
allowed, which is normally already permitted since most firewalls restrict
inbound traffic by default, not outbound.

The only place a port gets opened for *inbound* access is on the **manager**
side (in the lab's Docker network) — see `docker-compose.yml`'s
`wazuh-manager` service, and that's only reachable from the lab's own
network, not the internet.

## Deploy

```powershell
# Run as Administrator on the target Windows machine
.\Deploy-WazuhAgent.ps1 -ManagerHost 192.168.10.30
```

This downloads the official Wazuh agent MSI, installs it silently, enrolls it
with the manager, and starts the `WazuhSvc` service.

## Uninstall

```powershell
.\Deploy-WazuhAgent.ps1 -Uninstall
```

## Why syscheck (Wazuh's FIM) is disabled

`config/wazuh/shared-agent.conf` is mounted into the manager at
`/var/ossec/etc/shared/default/agent.conf` — Wazuh's standard mechanism for
pushing configuration to every agent in the "default" group automatically,
with no per-agent editing needed. It disables `<syscheck>` because this lab's
own FIM watcher already covers that ground with richer features (AD-user
attribution, rename/move/copy before-and-after paths, per-user ZIP restore)
that Wazuh's syscheck doesn't provide out of the box.

To use Wazuh's FIM instead: edit `config/wazuh/shared-agent.conf` to
`<disabled>no</disabled>`, restart `wazuh-manager`, and stop the custom
watcher on each endpoint with `Deploy-FIM.ps1 -Uninstall`.

## Where the data goes

The manager writes every alert locally to `/var/ossec/logs/alerts/alerts.json`
(no wazuh-indexer or wazuh-dashboard is deployed — this lab already runs
OpenSearch + Dashboards on the same ports those would use, 9200/5601, so
running both would be redundant). Vector tails that file directly and indexes
it into the same `soc-logs-*` index as everything else — query it with
`log_type: wazuh`.
