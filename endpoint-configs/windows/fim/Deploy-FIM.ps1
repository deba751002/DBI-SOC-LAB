#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab File Integrity Monitor - Deployment Script.
.DESCRIPTION
    Deploys the lightweight FIM watcher to this endpoint: no third-party agent
    install, just a native PowerShell script (FileSystemWatcher) registered as
    a Scheduled Task so it survives reboots and logons. Events are tagged with
    the signed-in AD identity and machine name, then forwarded to Vector.
.PARAMETER VectorHost
    Vector log aggregator host/IP (default: auto-detect from SOC_VECTOR_HOST env).
.PARAMETER VectorPort
    Vector FIM ingestion port (matches VECTOR_FIM_PORT in the lab's .env, default 6005).
.PARAMETER WatchedExtensions
    File extensions to monitor, e.g. ".docx",".xlsx",".pdf". Set by the admin -
    only files with these extensions are watched. Leave unset to keep the
    extensions already in fim-config.json.
.EXAMPLE
    .\Deploy-FIM.ps1 -VectorHost 192.168.10.30
.EXAMPLE
    .\Deploy-FIM.ps1 -VectorHost 192.168.10.30 -WatchedExtensions ".docx",".pdf",".zip"
.EXAMPLE
    .\Deploy-FIM.ps1 -Uninstall
#>
param(
    [string]$VectorHost = $(if ($env:SOC_VECTOR_HOST) { $env:SOC_VECTOR_HOST } else { "192.168.10.30" }),
    [int]$VectorPort = 6005,
    [string[]]$WatchedExtensions,
    [string]$InstallDir = "C:\ProgramData\SOCLab\FIM",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$taskName = "SOCLab-FileIntegrityMonitor"

if ($Uninstall) {
    Write-Host "Removing $taskName scheduled task and $InstallDir..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "Done. The custom FIM watcher is no longer running on this host." -ForegroundColor Green
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab File Integrity Monitor - Deployment       |" -ForegroundColor Cyan
Write-Host "|   No agent install - native PowerShell watcher      |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

# -- Step 1: Install files ------------------------------------------------------
Write-Host "[1/4] Installing watcher to $InstallDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\Watch-FileIntegrity.ps1" "$InstallDir\Watch-FileIntegrity.ps1" -Force

$configPath = "$InstallDir\fim-config.json"
$config = if (Test-Path $configPath) {
    Get-Content $configPath -Raw | ConvertFrom-Json
} else {
    Get-Content "$PSScriptRoot\fim-config.json" -Raw | ConvertFrom-Json
}

$config.forward_to_vector.host = $VectorHost
$config.forward_to_vector.port = $VectorPort
if ($WatchedExtensions) { $config.watched_extensions = $WatchedExtensions }

$config | ConvertTo-Json -Depth 5 | Out-File $configPath -Encoding UTF8
Write-Host "   Watched types: $($config.watched_extensions -join ', ')" -ForegroundColor White

# -- Step 2: Register Scheduled Task --------------------------------------------
Write-Host "[2/4] Registering Scheduled Task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallDir\Watch-FileIntegrity.ps1`" -ConfigPath `"$configPath`""
$trigger1  = New-ScheduledTaskTrigger -AtStartup
$trigger2  = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit 0

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) `
    -Principal $principal -Settings $settings -Description "SOC Lab lightweight file integrity watcher" | Out-Null

# -- Step 3: Start it now -------------------------------------------------------
Write-Host "[3/4] Starting watcher..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $taskName
Start-Sleep 2

# -- Step 4: Validate -----------------------------------------------------------
Write-Host "[4/4] Validating deployment..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Vector:      ${VectorHost}:${VectorPort}" -ForegroundColor White
Write-Host " Watched ext: $($config.watched_extensions -join ', ')" -ForegroundColor White
Write-Host " Log file:    $($config.log_path)" -ForegroundColor White
$stateOk = $task -and ($task.State -in @('Ready','Running'))
Write-Host " Task state:  $(if ($stateOk) {'OK - ' + $task.State} else {'FAILED - ' + $task.State})" -ForegroundColor $(if ($stateOk) {'Green'} else {'Red'})
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To change watched file types later, edit $configPath" -ForegroundColor Yellow
Write-Host "and re-run this script, OR edit it directly on the endpoint -" -ForegroundColor Yellow
Write-Host "the watcher re-reads it automatically every $($config.config_reload_seconds) seconds." -ForegroundColor Yellow
Write-Host ""
Write-Host "Verify in OpenSearch: index soc-logs-* | filter log_type: file_integrity, host: $env:COMPUTERNAME" -ForegroundColor Yellow
