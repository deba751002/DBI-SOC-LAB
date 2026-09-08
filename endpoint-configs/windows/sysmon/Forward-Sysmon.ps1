#Requires -Version 5.1
<#
.SYNOPSIS
    SOC Lab Sysmon forwarder - endpoint side.
.DESCRIPTION
    Polls the local "Microsoft-Windows-Sysmon/Operational" event log for new
    events (tracked by RecordId, so nothing is missed or double-sent across
    polls) and forwards each one as a single JSON line to Vector's dedicated
    windows_sysmon source (config/vector/vector.toml, TCP :6000), which already
    parses .EventID into a MITRE technique - no Wazuh agent involved, this is
    a separate, purpose-built pipeline.
.PARAMETER VectorHost
    Vector log aggregator host/IP.
.PARAMETER VectorPort
    Vector windows_sysmon ingestion port (matches sources.windows_sysmon in
    vector.toml, default 6000).
.PARAMETER PollSeconds
    How often to check for new Sysmon events.
.NOTES
    Intended to be launched by Deploy-Sysmon.ps1 via a Scheduled Task, but can
    be run directly in a console for testing: .\Forward-Sysmon.ps1
#>
param(
    [string]$VectorHost = "192.168.10.30",
    [int]$VectorPort = 6000,
    [int]$PollSeconds = 5
)

$ErrorActionPreference = "Stop"
$logName = "Microsoft-Windows-Sysmon/Operational"
$stateFile = "$PSScriptRoot\.last-record-id"

function Get-LastRecordId {
    if (Test-Path $stateFile) {
        try { return [int64](Get-Content $stateFile -Raw) } catch { return 0 }
    }
    return 0
}

function Set-LastRecordId {
    param([int64]$Id)
    Set-Content -Path $stateFile -Value $Id
}

function Send-SysmonEvent {
    param([string]$Json)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($VectorHost, $VectorPort)
        $stream = $client.GetStream()
        $bytes  = [System.Text.Encoding]::UTF8.GetBytes("$Json`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $client.Close()
    } catch {
        # Forwarding is best-effort - never let a network blip kill the poller.
    }
}

Write-Host "SOC Lab Sysmon forwarder running - shipping to ${VectorHost}:${VectorPort}"

while ($true) {
    try {
        $lastId = Get-LastRecordId
        $events = Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction SilentlyContinue |
                  Where-Object { $_.RecordId -gt $lastId } |
                  Sort-Object RecordId

        if ($events) {
            foreach ($evt in $events) {
                $dataFields = @{}
                try {
                    $xml = [xml]$evt.ToXml()
                    foreach ($d in $xml.Event.EventData.Data) {
                        if ($d.Name) { $dataFields[$d.Name] = $d.'#text' }
                    }
                } catch {}

                $payload = [ordered]@{
                    EventID     = $evt.Id
                    "@timestamp" = $evt.TimeCreated.ToUniversalTime().ToString("o")
                    Computer    = $evt.MachineName
                    RecordId    = $evt.RecordId
                    Image       = $dataFields["Image"]
                    CommandLine = $dataFields["CommandLine"]
                    User        = $dataFields["User"]
                    DestinationIp   = $dataFields["DestinationIp"]
                    DestinationPort = $dataFields["DestinationPort"]
                    TargetFilename  = $dataFields["TargetFilename"]
                    TargetObject    = $dataFields["TargetObject"]
                    QueryName       = $dataFields["QueryName"]
                }
                $json = $payload | ConvertTo-Json -Compress
                Send-SysmonEvent -Json $json
            }
            Set-LastRecordId -Id ($events | Select-Object -Last 1).RecordId
        }
    } catch {
        Write-Warning "Poll cycle failed: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $PollSeconds
}
