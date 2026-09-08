#Requires -Version 5.1
<#
.SYNOPSIS
    SOC Lab File Integrity Monitor - endpoint watcher.
.DESCRIPTION
    Watches the folders/extensions listed in fim-config.json for Created,
    Modified, Renamed/Moved and Deleted events using the native .NET
    FileSystemWatcher - no third-party agent required. Every matching event is
    written locally and forwarded (best-effort, non-blocking) as one JSON line
    to Vector, which tags it with a MITRE technique and indexes it into
    OpenSearch under soc-logs-*.

    The admin can change watched_extensions (and other settings except
    watch_paths) in fim-config.json at any time - this script re-reads the
    file every config_reload_seconds without needing a restart.

    LIMITATION: FileSystemWatcher cannot distinguish "copied" from "created"
    (both raise a Created event) - copies are logged as "created".
.PARAMETER ConfigPath
    Path to fim-config.json. Defaults to the copy next to this script.
.NOTES
    Intended to be launched by Deploy-FIM.ps1 via a Scheduled Task, but can be
    run directly in a console for testing: .\Watch-FileIntegrity.ps1
#>
param(
    [string]$ConfigPath = "$PSScriptRoot\fim-config.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) { throw "FIM config not found: $ConfigPath" }

function Read-FimConfig {
    param([string]$Path)
    Get-Content $Path -Raw | ConvertFrom-Json
}

$global:FimConfig     = Read-FimConfig -Path $ConfigPath
$global:FimConfigPath = $ConfigPath
$global:FimIdentity   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$global:FimMachine    = $env:COMPUTERNAME

New-Item -ItemType Directory -Force -Path (Split-Path $global:FimConfig.log_path) | Out-Null

function global:Test-FimWatchedExtension {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    return $global:FimConfig.watched_extensions -contains $ext
}

function global:Send-FimEvent {
    param(
        [string]$Action,
        [string]$FullPath,
        [string]$Destination = ""
    )
    if (-not (Test-FimWatchedExtension -Path $FullPath)) { return }

    $evt = [ordered]@{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
        action       = $Action
        user         = $global:FimIdentity
        machine      = $global:FimMachine
        file_path    = $FullPath
        destination  = $Destination
    }
    $json = $evt | ConvertTo-Json -Compress

    try { Add-Content -Path $global:FimConfig.log_path -Value $json } catch {}

    if ($global:FimConfig.forward_to_vector.enabled) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($global:FimConfig.forward_to_vector.host, [int]$global:FimConfig.forward_to_vector.port)
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes("$json`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
            $client.Close()
        } catch {
            # Forwarding is best-effort - never let a network blip kill the watcher.
        }
    }
}

# -- Set up one FileSystemWatcher per configured path --------------------------
$global:FimWatchers = @()
foreach ($rawPath in $global:FimConfig.watch_paths) {
    $path = [System.Environment]::ExpandEnvironmentVariables($rawPath)
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path                  = $path
    $watcher.IncludeSubdirectories = [bool]$global:FimConfig.include_subdirectories
    $watcher.Filter                = "*.*"
    $watcher.NotifyFilter          = [System.IO.NotifyFilters]'FileName, LastWrite, Size, DirectoryName'
    $watcher.EnableRaisingEvents   = $true

    Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "FIM_Created_$path" -Action {
        Send-FimEvent -Action "created" -FullPath $Event.SourceEventArgs.FullPath
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "FIM_Changed_$path" -Action {
        if ($Event.SourceEventArgs.ChangeType -eq [System.IO.WatcherChangeTypes]::Changed) {
            Send-FimEvent -Action "modified" -FullPath $Event.SourceEventArgs.FullPath
        }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Deleted -SourceIdentifier "FIM_Deleted_$path" -Action {
        Send-FimEvent -Action "deleted" -FullPath $Event.SourceEventArgs.FullPath
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier "FIM_Renamed_$path" -Action {
        $old = $Event.SourceEventArgs.OldFullPath
        $new = $Event.SourceEventArgs.FullPath
        $action = if ([System.IO.Path]::GetDirectoryName($old) -eq [System.IO.Path]::GetDirectoryName($new)) { "renamed" } else { "moved" }
        Send-FimEvent -Action $action -FullPath $new -Destination $old
    } | Out-Null

    $global:FimWatchers += $watcher
    Write-Host "Watching: $path (subfolders: $($watcher.IncludeSubdirectories))"
}

Write-Host "SOC Lab FIM watcher running. Watched types: $($global:FimConfig.watched_extensions -join ', ')"

# -- Idle loop: keep events flowing, hot-reload extensions/forwarding config ---
try {
    $lastReload = Get-Date
    while ($true) {
        Wait-Event -Timeout 5 | Remove-Event -ErrorAction SilentlyContinue

        $reloadEvery = 300
        if ($global:FimConfig.config_reload_seconds) { $reloadEvery = [int]$global:FimConfig.config_reload_seconds }

        if (((Get-Date) - $lastReload).TotalSeconds -ge $reloadEvery) {
            try {
                $global:FimConfig = Read-FimConfig -Path $global:FimConfigPath
                Write-Host "$(Get-Date -Format o)  Reloaded config - watched types: $($global:FimConfig.watched_extensions -join ', ')"
            } catch {
                Write-Warning "Config reload failed, keeping previous settings: $($_.Exception.Message)"
            }
            $lastReload = Get-Date
        }
    }
} finally {
    Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "FIM_*" } | Unregister-Event
    foreach ($w in $global:FimWatchers) { $w.Dispose() }
}
