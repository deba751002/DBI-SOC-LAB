# osquery — Endpoint Posture Queries

osquery exposes the operating system as a SQL-queryable table (processes,
listening ports, scheduled tasks, USB devices, ...). This lab schedules a
small query pack (`osquery.conf`) and ships the results to its own dedicated
Vector pipeline — separate from Wazuh and Sysmon, each of which already has
its own ingestion path, to avoid collecting the same signal three times.

## What's in the query pack

| Query | Interval | Why |
|---|---|---|
| `listening_ports` | 5 min | New/unexpected service — C2 or backdoor listener |
| `scheduled_tasks` | 10 min | Persistence — T1053.005 |
| `startup_items` | 10 min | Persistence — T1547.001 |
| `logged_in_users` | 5 min | Anomalous / after-hours logon |
| `processes_unsigned` | 5 min | Process running outside `C:\Windows`, with a hash for lookup |
| `usb_devices` | 2 min | Exfiltration path — T1052.001 |

## Firewall / port impact

**No inbound port opened on the endpoint.** `Forward-Osquery.ps1` tails
osqueryd's local results log file and makes an outbound TCP connection to
Vector (default port 6007) — the same one-way pattern as the FIM watcher,
the Sysmon forwarder, and the Wazuh agent.

## Deploy

```powershell
# Run as Administrator
.\Deploy-Osquery.ps1 -VectorHost 192.168.10.30
```

This installs osqueryd, drops `osquery.conf` into
`C:\ProgramData\osquery\`, and registers `Forward-Osquery.ps1` as a Scheduled
Task (`SOCLab-OsqueryForwarder`) that tails the results log and forwards new
lines to `${VectorHost}:6007`.

## Uninstall

```powershell
.\Deploy-Osquery.ps1 -Uninstall
```

## Where the data goes

`Forward-Osquery.ps1` -> Vector `sources.osquery` (:6007) ->
`transforms.parse_osquery` (adds `log_type: osquery`, `host.name`, and a
MITRE technique based on which scheduled query fired) -> `soc-logs-*` in
OpenSearch. Filter on `log_type: osquery` and `query_name` to isolate a
specific check.
