#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab Wazuh Agent Installer (Windows).
.DESCRIPTION
    Downloads and silently installs the official Wazuh Windows agent, enrolls
    it with this lab's Wazuh manager, and starts the WazuhSvc service.

    This agent connects OUTBOUND to the manager on TCP 1514 (data) and 1515
    (enrollment, first run only) - it does not open or listen on any new
    inbound port on this endpoint.

    File Integrity Monitoring (syscheck) is disabled for this agent via the
    manager's shared configuration (config/wazuh/shared-agent.conf) - this
    lab uses its own custom FIM watcher instead (see
    endpoint-configs/windows/fim/). No local change is needed here for that;
    it is centrally enforced by the manager.
.PARAMETER ManagerHost
    IP or hostname of the Wazuh manager (default: auto-detect from
    SOC_VECTOR_HOST env, since the manager typically runs on the same lab
    host as everything else).
.PARAMETER AgentVersion
    Wazuh agent version to install. Must match (or be compatible with) the
    manager version in docker-compose.yml (currently 4.7.5).
.EXAMPLE
    .\Deploy-WazuhAgent.ps1 -ManagerHost 192.168.10.30
.EXAMPLE
    .\Deploy-WazuhAgent.ps1 -Uninstall
#>
param(
    [string]$ManagerHost = $(if ($env:SOC_VECTOR_HOST) { $env:SOC_VECTOR_HOST } else { "192.168.10.30" }),
    [string]$AgentVersion = "4.7.5",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

if ($Uninstall) {
    Write-Host "Uninstalling Wazuh agent..." -ForegroundColor Yellow
    Stop-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    $product = Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Wazuh Agent%'" -ErrorAction SilentlyContinue
    if ($product) { $product.Uninstall() | Out-Null }
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab Wazuh Agent Installer                     |" -ForegroundColor Cyan
Write-Host "|   Host-based EDR - syscheck disabled (see FIM tab)  |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

# -- Step 1: Download the agent MSI ------------------------------------------
Write-Host "[1/3] Downloading Wazuh agent $AgentVersion..." -ForegroundColor Yellow
$msiUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AgentVersion-1.msi"
$msiPath = "$env:TEMP\wazuh-agent-$AgentVersion.msi"
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

# -- Step 2: Silent install + enroll with the manager -------------------------
Write-Host "[2/3] Installing and enrolling with manager $ManagerHost..." -ForegroundColor Yellow
$msiArgs = @(
    "/i", "`"$msiPath`"",
    "/q",
    "WAZUH_MANAGER=`"$ManagerHost`"",
    "WAZUH_REGISTRATION_SERVER=`"$ManagerHost`""
)
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "msiexec failed with exit code $($proc.ExitCode)" }

Start-Service -Name WazuhSvc
Start-Sleep 3

# -- Step 3: Validate ---------------------------------------------------------
Write-Host "[3/3] Validating deployment..." -ForegroundColor Yellow
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Manager:     ${ManagerHost}:1514 (data) / :1515 (enrollment)" -ForegroundColor White
Write-Host " Service:     $(if ($svc.Status -eq 'Running') {'OK - Running'} else {'FAILED - ' + $svc.Status})" -ForegroundColor $(if ($svc.Status -eq 'Running') {'Green'} else {'Red'})
Write-Host " Config path: C:\Program Files (x86)\ossec-agent\ossec.conf" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: no new inbound firewall port is required on this host - the" -ForegroundColor Yellow
Write-Host "agent only makes outbound connections to the manager." -ForegroundColor Yellow
Write-Host ""
Write-Host "Verify in OpenSearch: index soc-logs-* | filter log_type: wazuh, host.name: $env:COMPUTERNAME" -ForegroundColor Yellow
