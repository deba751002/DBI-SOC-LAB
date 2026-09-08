# File Integrity Monitoring (FIM) — Endpoint Watcher

Lightweight file integrity monitoring for Windows endpoints. No third-party
agent — just a native PowerShell script (`System.IO.FileSystemWatcher`)
registered as a Scheduled Task, so there's nothing to install beyond copying
two files.

## What it watches

Every Created, Modified, Renamed, Moved and Deleted event on the folders
listed in `fim-config.json`, filtered to the file extensions the admin
configures there. Each event is tagged with:

- the signed-in AD identity (`DOMAIN\user`)
- the machine name
- the full file path (and previous path, for renames/moves)
- a UTC timestamp

Events are written to a local log (`C:\ProgramData\SOCLab\FIM\fim-events.log`
by default) and forwarded over TCP to Vector, which tags them with a MITRE
technique and indexes them into OpenSearch (`soc-logs-*`) alongside every
other log source in the lab. They show up on the **File Integrity** dashboard
tab in the SOC portal.

**Limitation:** `FileSystemWatcher` cannot tell a copy apart from a brand-new
file — both raise a `Created` event, so copies are logged as `created`.

## Deploy to an endpoint

```powershell
# Run as Administrator on the target machine
.\Deploy-FIM.ps1 -VectorHost 192.168.10.30
```

This copies `Watch-FileIntegrity.ps1` + `fim-config.json` to
`C:\ProgramData\SOCLab\FIM\`, registers a Scheduled Task
(`SOCLab-FileIntegrityMonitor`) that runs at startup and logon as SYSTEM, and
starts it immediately.

To roll this out to many machines, push the `fim` folder + a GPO startup
script (or an RMM/Intune script deployment) that runs `Deploy-FIM.ps1
-VectorHost <your-vector-host>` — the same pattern as `install-agent.ps1` in
the parent folder.

## Configuring which file types are watched

`fim-config.json` is the single source of truth:

```json
{
  "watch_paths": ["%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "..."],
  "include_subdirectories": true,
  "watched_extensions": [".docx", ".xlsx", ".pptx", ".pdf", ".csv", ".txt", ".zip"],
  "log_path": "C:\\ProgramData\\SOCLab\\FIM\\fim-events.log",
  "config_reload_seconds": 300,
  "forward_to_vector": { "enabled": true, "host": "vector.soc.lab", "port": 6005 }
}
```

Two ways to change `watched_extensions`:

1. **Redeploy:** `.\Deploy-FIM.ps1 -VectorHost 192.168.10.30 -WatchedExtensions ".docx",".pdf",".zip"`
2. **Edit in place:** change `watched_extensions` directly in
   `C:\ProgramData\SOCLab\FIM\fim-config.json` on the endpoint — the running
   watcher re-reads the file every `config_reload_seconds` (default 5 min), no
   restart needed.

`watch_paths` changes require re-running `Deploy-FIM.ps1` (or restarting the
Scheduled Task) since the `FileSystemWatcher` objects are created once at
startup.

## Testing locally

```powershell
# From this folder, without installing anything:
.\Watch-FileIntegrity.ps1 -ConfigPath .\fim-config.json
```

Then create/edit/rename/delete a file with a watched extension under one of
`watch_paths` and watch the console output and `fim-events.log`.
