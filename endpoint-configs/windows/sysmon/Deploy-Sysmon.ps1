#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab Sysmon Installer (Windows).
.DESCRIPTION
    Downloads and installs Sysmon with this lab's baseline config, then
    registers a lightweight PowerShell forwarder (Forward-Sysmon.ps1) as a
    Scheduled Task that ships events to Vector's dedicated windows_sysmon
    ingestion point (config/vector/vector.toml, TCP :6000). This is a
    separate pipeline from Wazuh - it is not routed through the Wazuh agent,
    to avoid double-alerting the same events through two paths.
.PARAMETER VectorHost
    Vector log aggregator host/IP (default: auto-detect from SOC_VECTOR_HOST env).
.PARAMETER VectorPort
    Vector windows_sysmon ingestion port (matches sources.windows_sysmon in
    vector.toml, default 6000).
.PARAMETER ConfigPath
    Path to the Sysmon XML config. Defaults to sysmonconfig.xml next to
    this script.
.EXAMPLE
    .\Deploy-Sysmon.ps1 -VectorHost 192.168.10.30
.EXAMPLE
    .\Deploy-Sysmon.ps1 -Uninstall
#>
param(
    [string]$VectorHost = $(if ($env:SOC_VECTOR_HOST) { $env:SOC_VECTOR_HOST } else { "192.168.10.30" }),
    [int]$VectorPort = 6000,
    [string]$ConfigPath = "$PSScriptRoot\sysmonconfig.xml",
    [string]$InstallDir = "C:\ProgramData\SOCLab\Sysmon",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$sysmonInstallDir      = "C:\Program Files\Sysmon"
$sysmonExe             = "$sysmonInstallDir\Sysmon64.exe"
$taskName              = "SOCLab-SysmonForwarder"

if ($Uninstall) {
    Write-Host "Uninstalling Sysmon forwarder and Sysmon..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    if (Test-Path $sysmonExe) {
        Start-Process -FilePath $sysmonExe -ArgumentList "-u", "force" -Wait -NoNewWindow
    }
    Remove-Item -Path $sysmonInstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab Sysmon Installer                          |" -ForegroundColor Cyan
Write-Host "|   Deep endpoint telemetry -> Vector (not via Wazuh) |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

# -- Step 1: Download and install Sysmon -------------------------------------
Write-Host "[1/4] Downloading and installing Sysmon..." -ForegroundColor Yellow
$zipUrl  = "https://download.sysinternals.com/files/Sysmon.zip"
$zipPath = "$env:TEMP\Sysmon.zip"
$extractPath = "$env:TEMP\Sysmon"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

New-Item -ItemType Directory -Path $sysmonInstallDir -Force | Out-Null
Copy-Item -Path "$extractPath\Sysmon64.exe" -Destination $sysmonExe -Force
Copy-Item -Path $ConfigPath -Destination "$sysmonInstallDir\sysmonconfig.xml" -Force

$proc = Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula", "-i", "`"$sysmonInstallDir\sysmonconfig.xml`"" -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) { throw "Sysmon install failed with exit code $($proc.ExitCode)" }

# -- Step 2: Install the forwarder -------------------------------------------
Write-Host "[2/4] Installing Sysmon forwarder to $InstallDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\Forward-Sysmon.ps1" "$InstallDir\Forward-Sysmon.ps1" -Force

# -- Step 3: Register Scheduled Task ------------------------------------------
Write-Host "[3/4] Registering Scheduled Task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallDir\Forward-Sysmon.ps1`" -VectorHost `"$VectorHost`" -VectorPort $VectorPort"
$trigger1  = New-ScheduledTaskTrigger -AtStartup
$trigger2  = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit 0

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) `
    -Principal $principal -Settings $settings -Description "SOC Lab Sysmon event forwarder" | Out-Null

Start-ScheduledTask -TaskName $taskName
Start-Sleep 2

# -- Step 4: Validate ----------------------------------------------------------
Write-Host "[4/4] Validating deployment..." -ForegroundColor Yellow
$sysmonSvc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name Sysmon -ErrorAction SilentlyContinue }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:          $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Sysmon config: $sysmonInstallDir\sysmonconfig.xml" -ForegroundColor White
Write-Host " Vector:        ${VectorHost}:${VectorPort} (windows_sysmon source)" -ForegroundColor White
$sysmonOk = $sysmonSvc -and $sysmonSvc.Status -eq 'Running'
$taskOk   = $task -and ($task.State -in @('Ready','Running'))
Write-Host " Sysmon svc:    $(if ($sysmonOk) {'OK - Running'} else {'FAILED'})" -ForegroundColor $(if ($sysmonOk) {'Green'} else {'Red'})
Write-Host " Forwarder:     $(if ($taskOk) {'OK - ' + $task.State} else {'FAILED'})" -ForegroundColor $(if ($taskOk) {'Green'} else {'Red'})
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify in OpenSearch: soc-logs-* | filter log_type: sysmon, host.name: $env:COMPUTERNAME" -ForegroundColor Yellow
