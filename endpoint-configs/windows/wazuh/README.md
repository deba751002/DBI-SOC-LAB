# Wazuh Agent — Endpoint Deployment

Host-based EDR: log collection, active response, and its own CVE vulnerability
detector. This project's Wazuh is now the org's real, externally-managed
deployment (`siem.dbi360.com`) — not a local manager this repo controls — so
this section no longer manages the manager's shared agent config (including
whether syscheck, Wazuh's own FIM, is enabled). This lab's own File Integrity
Monitoring watcher (`endpoint-configs/windows/fim/`) still runs independently
and may overlap with syscheck's alerts; that overlap is accepted rather than
suppressed, since the manager's config isn't ours to edit anymore.

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

The manager itself lives outside this repo entirely now (an EC2-hosted,
org-managed Wazuh) — its own security group controls who can reach it, not
anything in this `docker-compose.yml`.

## Deploy

```powershell
# Run as Administrator on the target Windows machine
.\Deploy-WazuhAgent.ps1 -ManagerHost <manager private IP, e.g. 10.2.131.158>
```

This downloads the official Wazuh agent MSI, installs it silently, enrolls it
with the manager, and starts the `WazuhSvc` service. Use the manager's actual
reachable address (typically its private IP over the org's VPN) — the public
hostname (e.g. `siem.dbi360.com`) usually only routes to the web dashboard
(443) through a load balancer that doesn't forward 1514/1515 at all.

## Uninstall

```powershell
.\Deploy-WazuhAgent.ps1 -Uninstall
```

## Where the data goes

This project no longer reads the manager's local `alerts.json` file directly
(that only worked for the retired local manager). Alerts now reach this
lab's `soc-logs-*` OpenSearch index via `wazuh-remote-connector/poller.py`,
which polls the manager's own indexer — see the "Wazuh EDR" section in the
top-level `README.md`. Query with `log_type: wazuh-remote`.
