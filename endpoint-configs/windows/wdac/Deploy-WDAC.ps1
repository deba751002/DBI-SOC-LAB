#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab WDAC (Windows Defender Application Control) Deployer.
.DESCRIPTION
    Deploys this lab's FIRST prevention-focused endpoint control - everything
    else deployed so far (Wazuh, Sysmon, osquery, FIM) only detects and
    reports; WDAC actually blocks execution of anything not covered by the
    policy's rules.

    Deliberately does NOT hand-author a custom policy XML from scratch - a
    malformed WDAC policy can make a machine unable to run anything, so this
    script follows Microsoft's own recommended path: generate the policy from
    what is actually installed on this machine (New-CIPolicy, Publisher-level
    rules with a hash fallback), and deploy it in AUDIT mode first. Audit mode
    logs what WOULD have been blocked (Event ID 3076) without blocking
    anything - review those logs before ever switching to enforced mode.
.PARAMETER PolicyName
    Friendly name for the generated policy.
.EXAMPLE
    .\Deploy-WDAC.ps1
.EXAMPLE
    .\Deploy-WDAC.ps1 -Uninstall
#>
param(
    [string]$PolicyName = "SOCLab-WDAC-Audit",
    [string]$WorkDir = "C:\ProgramData\SOCLab\WDAC",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$activeDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"

if ($Uninstall) {
    Write-Host "Removing SOC Lab WDAC policy..." -ForegroundColor Yellow
    Get-ChildItem $activeDir -Filter "*.cip" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Found active policy: $($_.Name) - remove manually with care, this cmdlet does not auto-detect which GUID is ours." -ForegroundColor Yellow
    }
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Work directory removed. Active .cip policies must be removed by hand (see path above) and the machine restarted." -ForegroundColor Yellow
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab WDAC Deployer                             |" -ForegroundColor Cyan
Write-Host "|   AUDIT MODE ONLY - review logs before enforcing   |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ConfigCI)) {
    throw "ConfigCI module not found - this requires Windows 10/11 Enterprise or Education, or Windows Server 2016+."
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$policyXml = "$WorkDir\$PolicyName.xml"
$policyBin = "$WorkDir\$PolicyName.cip"

# -- Step 1: Scan this machine's installed software to build the ruleset -----
Write-Host "[1/4] Scanning installed software (this can take a few minutes)..." -ForegroundColor Yellow
New-CIPolicy -FilePath $policyXml -Level Publisher -Fallback Hash -UserPEs -ScanPath "C:\Program Files","C:\Program Files (x86)" -MultiplePolicyFormat

# -- Step 2: Force audit mode - never deploy straight to enforced ------------
Write-Host "[2/4] Setting policy to AUDIT mode (Option 3)..." -ForegroundColor Yellow
Set-RuleOption -FilePath $policyXml -Option 3

# -- Step 3: Convert to binary and deploy ------------------------------------
Write-Host "[3/4] Converting to binary and deploying..." -ForegroundColor Yellow
ConvertFrom-CIPolicy -XmlFilePath $policyXml -BinaryFilePath $policyBin
New-Item -ItemType Directory -Force -Path $activeDir | Out-Null
Copy-Item -Path $policyBin -Destination "$activeDir\$PolicyName.cip" -Force

# -- Step 4: Summary ----------------------------------------------------------
Write-Host "[4/4] Done." -ForegroundColor Yellow

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Mode:        AUDIT ONLY - nothing is blocked yet" -ForegroundColor White
Write-Host " Policy file: $activeDir\$PolicyName.cip" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "REBOOT REQUIRED for the policy to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "After reboot, review audit hits before ever enforcing:" -ForegroundColor Yellow
Write-Host "  Event Viewer -> Applications and Services Logs -> Microsoft ->" -ForegroundColor Yellow
Write-Host "  Windows -> CodeIntegrity/Operational -> Event ID 3076" -ForegroundColor Yellow
Write-Host ""
Write-Host "Only after confirming zero unexpected blocks over at least a" -ForegroundColor Yellow
Write-Host "week of normal use: re-run Set-RuleOption -FilePath $policyXml -Option 3 -Delete" -ForegroundColor Yellow
Write-Host "to remove audit mode, then re-convert and redeploy to enforce." -ForegroundColor Yellow
