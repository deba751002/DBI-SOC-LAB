# Sysmon — Deep Endpoint Telemetry

Sysmon logs process creation, network connections, image/DLL loads, file
creates, and registry changes to a local Windows Event Log channel. This
lab ships those events straight to Vector's own dedicated ingestion point —
not through the Wazuh agent — so the same events are never double-counted
across two pipelines.

## Why a dedicated pipeline instead of routing through Wazuh

`config/vector/vector.toml` already has a `sources.windows_sysmon` socket
(TCP :6000) with its own MITRE-technique mapping in `transforms.parse_windows`
(EventID 1/3/7/8/10/11/13/22 -> ATT&CK techniques) — this was scaffolded before
anything on the endpoint side actually fed it. Routing Sysmon through the
Wazuh agent instead would create the exact duplicate-alerting problem this
lab's own `config/wazuh/shared-agent.conf` already documents and avoids for
FIM (its custom watcher vs. Wazuh's syscheck) — so Sysmon gets its own
forwarder here rather than reusing the Wazuh path.

## Firewall / port impact

**No inbound port opened on the endpoint.** `Forward-Sysmon.ps1` only makes
an outbound TCP connection to Vector (default port 6000) each time it ships
a batch of events — same one-way pattern as the FIM watcher and the Wazuh
agent.

## Deploy

```powershell
# Run as Administrator
.\Deploy-Sysmon.ps1 -VectorHost 192.168.10.30
```

This:
1. Downloads Sysmon from the official Microsoft Sysinternals live tools site
   and installs it with `sysmonconfig.xml` (this lab's trimmed baseline).
2. Copies `Forward-Sysmon.ps1` to `C:\ProgramData\SOCLab\Sysmon\`.
3. Registers it as a Scheduled Task (`SOCLab-SysmonForwarder`, runs at
   startup/logon as SYSTEM) that polls the Sysmon event log every 5 seconds
   and forwards new events as JSON to `${VectorHost}:6000`.

## Uninstall

```powershell
.\Deploy-Sysmon.ps1 -Uninstall
```

Removes the scheduled task and uninstalls Sysmon.

## Where the data goes

`Forward-Sysmon.ps1` -> Vector `sources.windows_sysmon` (:6000) ->
`transforms.parse_windows` (adds `log_type: sysmon`, `host.name`, and a MITRE
technique from the event's `EventID`) -> `soc-logs-*` in OpenSearch. Filter on
`log_type: sysmon` to isolate this from the Wazuh alert stream.
