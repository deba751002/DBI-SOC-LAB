# File Integrity Monitoring (FIM) — Endpoint Watcher (DLP-lite)

Lightweight file activity monitoring for Windows endpoints — deliberately not
a simple FIM checksum tool. No third-party agent, no new listening port — just
a native PowerShell script (`System.IO.FileSystemWatcher`) registered as a
Scheduled Task, so it adds zero attack surface beyond the outbound TCP
connection it already makes to Vector. This is the single endpoint watcher
the lab standardizes on instead of deploying multiple agents.

## What it watches

Every Created, Modified, Renamed, Moved, Copied and Deleted event on the
folders listed in `fim-config.json`, filtered to the file extensions the admin
configures there. Each event is tagged with:

- the signed-in AD identity (`DOMAIN\user`) and machine name
- the full file path (and, for renames/moves/copies, the correlated
  source/previous path)
- a UTC timestamp, SHA256 hash and size
- a bounded **content preview** (see below) — so an analyst can see what was
  inside the file without downloading it
- a **recoverable** flag — `true` when a shadow copy of the file's bytes is
  available, meaning a `deleted` event can be restored exactly, not just
  logged as metadata

Events are written to a local log (`C:\ProgramData\SOCLab\FIM\fim-events.log`
by default) and forwarded over TCP to Vector, which tags them with a MITRE
technique and indexes them into OpenSearch (`soc-logs-*`) alongside every
other log source in the lab. They show up on the **File Integrity** dashboard
tab in the SOC portal, backed by real ws-streamer endpoints
(`/api/fim/events`, `/api/fim/restore/{id}`) — not sample data.

## How copy/move detection and recovery actually work

`FileSystemWatcher` itself only ever tells you Created / Changed / Deleted /
Renamed — it cannot natively tell a copy from a new file, or correlate a
delete in one folder with a create in another. This script adds a layer on
top to approximate what's needed:

- **Shadow copy store** (`shadow_copy.path`, default
  `C:\ProgramData\SOCLab\FIM\ShadowCopies\<sha256>`): every watched file's
  content is copied here (deduped by hash, capped at `shadow_copy.max_file_mb`
  per file and `shadow_copy.max_store_mb` total) whenever it's created or
  modified, and once via a **startup baseline scan** of files that already
  existed before the watcher started. When a file is deleted, its last-known
  bytes are already sitting in this store — that's what makes a `deleted`
  event's `content_b64`/`recoverable` fields possible; the endpoint is never
  contacted again after the fact, since there is no inbound channel to it.
- **Copy detection**: on a `Created` event, the new file's hash is compared
  against every other *currently-existing* watched file's last-known hash. A
  match means identical content already exists elsewhere → logged as `copied`
  with the matching path as the source.
- **Cross-directory move detection**: a native `Renamed` event already covers
  same-machine moves within one FileSystemWatcher root. For a move that looks
  like delete-then-create (e.g. across two separately-watched roots, or via
  some sync/cloud clients), a short correlation window
  (`move_correlation_window_seconds`, default 30s) matches a `Deleted` event's
  hash against a subsequent `Created` event's hash and re-labels it `moved`.
- **Content preview**: `.txt`/`.csv` are read as plain text; `.docx`/`.xlsx`/
  `.pptx` (all zip containers) have their XML text parts extracted and
  tag-stripped; `.zip` lists entry names only; everything else (notably
  `.pdf`) falls back to a placeholder — this build has no PDF text-layer
  parser, so a PDF's exact content can only be recovered via download/restore,
  not previewed inline.
- **Periodic reconciliation scan** (`reconciliation_scan_seconds`, default
  120s): `FileSystemWatcher`'s real-time notifications can be silently
  suppressed by things entirely outside this script's control — observed in
  real endpoint testing, an org-managed antivirus/EDR's filesystem filter
  driver occasionally swallowed change notifications with no error raised
  anywhere, no exception to catch, nothing. Rather than trust real-time
  delivery alone, the watcher periodically re-walks every watched path and
  diffs against last-known state (skipping the hash check entirely for files
  whose size+mtime haven't changed, to keep this cheap), generating the exact
  same created/modified/deleted events - with the same hash correlation,
  shadow copy and content preview - that the real-time watcher would have
  produced. A missed real-time notification is caught within one
  reconciliation interval instead of never. This mirrors why Wazuh's own FIM
  module (`syscheck`) pairs real-time watching with a periodic full scan
  rather than relying on real-time delivery by itself.
- **Diagnostics** (`fim-diag.log`, next to `fim-events.log`): records every
  raw `FileSystemWatcher` event as it fires (before any of this script's own
  logic runs) and any exception caught from inside an event handler -
  `Register-ObjectEvent` action scriptblocks fail completely silently
  otherwise (their errors land in a background `PSEventJob` nobody
  inspects), which made a real reliability issue undiagnosable until this
  was added.

**Honesty about limitations — this is heuristic, not forensic-grade:**

- Copy/move correlation is by content hash. Two *different, unrelated* files
  that happen to have byte-identical content will look like a copy of each
  other. In a small lab this is a rare and acceptable margin of error, not a
  guarantee you'd want to cite in a legal proceeding.
- The in-memory "known files" map used for copy detection is rebuilt from a
  startup baseline scan — very large watched trees or a script restart right
  as a copy happens can miss a correlation (it'll still log a plain
  `created`, just without the source link).
- Shadow copies (and therefore recovery + exact restore) are skipped for any
  file over `shadow_copy.max_file_mb` — those still get full metadata +
  preview, just not byte-exact recovery.
- PDF and ZIP contents are not text-previewed, only recoverable via restore.

## Deploy to an endpoint

```powershell
# Run as Administrator on the target machine
.\Deploy-FIM.ps1 -VectorHost 192.168.10.30
```

This copies `Watch-FileIntegrity.ps1` + `fim-config.json` to
`C:\ProgramData\SOCLab\FIM\`, registers a Scheduled Task
(`SOCLab-FileIntegrityMonitor`) that runs on logon **as whichever user signs
in** (not SYSTEM — `watch_paths` uses `%USERPROFILE%\...`, which only resolves
to a real person's Desktop/Documents/Downloads under their own session; under
SYSTEM it resolves to `C:\Windows\System32\config\systemprofile` and silently
watches nothing), auto-restarts within a minute if it ever crashes, and starts
it immediately. `Deploy-FIM.ps1` itself still needs to run elevated (it writes
to `ProgramData` and registers the task) — only the resulting watcher process
runs in the signed-in user's own context.

To roll this out to many machines, push the `fim` folder + a GPO startup
script (or an RMM/Intune script deployment) that runs `Deploy-FIM.ps1
-VectorHost <your-vector-host>` — the same pattern as `install-agent.ps1` in
the parent folder.

### Deploying via ManageEngine Endpoint Central

Since `Deploy-FIM.ps1` is self-contained, silent (no prompts) and idempotent
(safe to run again — it unregisters/re-registers the task each time), it can
be pushed as a plain **Custom Script** deployment/configuration rather than a
packaged installer:

1. In the Endpoint Central console (`https://192.168.30.6:8443` or
   `https://secops.dbi360.com`), go to **Configurations → Custom Script** (or
   **Software Deployment → Script Configuration**, depending on your build)
   and add a new configuration.
2. Upload this whole `fim` folder as the script's associated files (so
   `Watch-FileIntegrity.ps1` and `fim-config.json` sit next to
   `Deploy-FIM.ps1` on the endpoint at execution time — Endpoint Central
   stages all associated files into the same working directory it runs the
   script from).
3. Script to execute: `Deploy-FIM.ps1 -VectorHost 192.168.30.206`. Endpoint
   Central runs deployment scripts as SYSTEM by default — that's fine and
   expected here: SYSTEM only needs to install the files and register the
   Scheduled Task; the task itself is defined to run the actual watcher as
   whichever user later logs on (`BUILTIN\Users` + `LogonType Interactive`,
   see above), not as SYSTEM.
4. Target it at a device group (start with just the one test laptop) and
   deploy — Endpoint Central's own deployment status view confirms the script
   ran and its exit code; that's install success, not proof events are
   flowing.
5. To actually confirm data is flowing, check the SOC dashboard's **File
   Integrity** tab (or `curl http://<soc-server>:8766/api/fim/events`) after
   the target user next logs on and touches a watched file — the two systems
   (ManageEngine's own deployment status, and this lab's ws-streamer/
   OpenSearch) are independent and both need to say yes.

No new inbound port is opened on the endpoint by any of this — Endpoint
Central pushes the script over its own existing agent channel, and the
watcher itself only ever makes outbound connections to Vector.

## Configuring which file types are watched

`fim-config.json` is the single source of truth:

```json
{
  "watch_paths": ["%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "..."],
  "include_subdirectories": true,
  "watched_extensions": [".docx", ".xlsx", ".pptx", ".pdf", ".csv", ".txt", ".zip"],
  "log_path": "C:\\ProgramData\\SOCLab\\FIM\\fim-events.log",
  "config_reload_seconds": 300,
  "forward_to_vector": { "enabled": true, "host": "vector.soc.lab", "port": 6005 },
  "shadow_copy": { "enabled": true, "path": "C:\\ProgramData\\SOCLab\\FIM\\ShadowCopies", "max_file_mb": 20, "max_store_mb": 2048 },
  "content_preview": { "enabled": true, "max_chars": 4000 },
  "move_correlation_window_seconds": 30,
  "reconciliation_scan_seconds": 120
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
