#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab osquery Installer (Windows).
.DESCRIPTION
    Installs osquery with this lab's query pack (osquery.conf - listening
    ports, scheduled tasks, startup items, logged-in users, unsigned
    processes, USB devices), then registers a lightweight forwarder
    (Forward-Osquery.ps1) as a Scheduled Task that tails osqueryd's local
    results log and ships new lines to Vector's dedicated osquery source
    (config/vector/vector.toml, TCP :6007) - a separate pipeline from Wazuh
    and Sysmon, so the same posture data isn't double-collected.
.PARAMETER VectorHost
    Vector log aggregator host/IP (default: auto-detect from SOC_VECTOR_HOST env).
.PARAMETER VectorPort
    Vector osquery ingestion port (matches sources.osquery in vector.toml,
    default 6007).
.PARAMETER ConfigPath
    Path to osquery.conf. Defaults to the copy next to this script.
.EXAMPLE
    .\Deploy-Osquery.ps1 -VectorHost 192.168.10.30
.EXAMPLE
    .\Deploy-Osquery.ps1 -Uninstall
#>
param(
    [string]$VectorHost = $(if ($env:SOC_VECTOR_HOST) { $env:SOC_VECTOR_HOST } else { "192.168.10.30" }),
    [int]$VectorPort = 6007,
    [string]$ConfigPath = "$PSScriptRoot\osquery.conf",
    [string]$InstallDir = "C:\ProgramData\SOCLab\osquery",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$osqueryProgramDir     = "C:\Program Files\osquery"
$osqueryConfDir        = "C:\ProgramData\osquery"
$taskName              = "SOCLab-OsqueryForwarder"

if ($Uninstall) {
    Write-Host "Uninstalling osquery forwarder and osqueryd..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Service -Name osqueryd -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    $product = Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'osquery%'" -ErrorAction SilentlyContinue
    if ($product) { $product.Uninstall() | Out-Null }
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab osquery Installer                         |" -ForegroundColor Cyan
Write-Host "|   Endpoint posture queries -> Vector (own pipeline) |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

# -- Step 1: Download and install osquery -------------------------------------
Write-Host "[1/4] Downloading and installing osquery..." -ForegroundColor Yellow
$msiUrl  = "https://pkg.osquery.io/windows/osquery-5.13.1.msi"
$msiPath = "$env:TEMP\osquery.msi"
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`"$msiPath`"", "/q" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "osquery install failed with exit code $($proc.ExitCode)" }

New-Item -ItemType Directory -Force -Path $osqueryConfDir | Out-Null
New-Item -ItemType Directory -Force -Path "$osqueryConfDir\log" | Out-Null
Copy-Item -Path $ConfigPath -Destination "$osqueryConfDir\osquery.conf" -Force

Start-Service -Name osqueryd -ErrorAction SilentlyContinue
Start-Sleep 3

# -- Step 2: Install the forwarder --------------------------------------------
Write-Host "[2/4] Installing osquery forwarder to $InstallDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\Forward-Osquery.ps1" "$InstallDir\Forward-Osquery.ps1" -Force

# -- Step 3: Register Scheduled Task -------------------------------------------
Write-Host "[3/4] Registering Scheduled Task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallDir\Forward-Osquery.ps1`" -VectorHost `"$VectorHost`" -VectorPort $VectorPort"
$trigger1  = New-ScheduledTaskTrigger -AtStartup
$trigger2  = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit 0

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) `
    -Principal $principal -Settings $settings -Description "SOC Lab osquery results forwarder" | Out-Null

Start-ScheduledTask -TaskName $taskName
Start-Sleep 2

# -- Step 4: Validate -----------------------------------------------------------
Write-Host "[4/4] Validating deployment..." -ForegroundColor Yellow
$svc  = Get-Service -Name osqueryd -ErrorAction SilentlyContinue
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Config:      $osqueryConfDir\osquery.conf" -ForegroundColor White
Write-Host " Vector:      ${VectorHost}:${VectorPort} (osquery source)" -ForegroundColor White
$svcOk  = $svc -and $svc.Status -eq 'Running'
$taskOk = $task -and ($task.State -in @('Ready','Running'))
Write-Host " osqueryd:    $(if ($svcOk) {'OK - Running'} else {'FAILED'})" -ForegroundColor $(if ($svcOk) {'Green'} else {'Red'})
Write-Host " Forwarder:   $(if ($taskOk) {'OK - ' + $task.State} else {'FAILED'})" -ForegroundColor $(if ($taskOk) {'Green'} else {'Red'})
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify in OpenSearch: soc-logs-* | filter log_type: osquery, host.name: $env:COMPUTERNAME" -ForegroundColor Yellow
