#Requires -Version 5.1
<#
.SYNOPSIS
    SOC Lab osquery forwarder - endpoint side.
.DESCRIPTION
    Tails osqueryd's local results log (one JSON object per line, written by
    the "filesystem" logger_plugin in osquery.conf) and forwards each new
    line to Vector's dedicated osquery source (config/vector/vector.toml,
    TCP :6007). Tracks a byte offset so restarts don't re-send old lines or
    miss ones written while the forwarder wasn't running.
.PARAMETER VectorHost
    Vector log aggregator host/IP.
.PARAMETER VectorPort
    Vector osquery ingestion port (matches sources.osquery in vector.toml,
    default 6007).
.PARAMETER ResultsLogPath
    Path to osqueryd's results log.
.PARAMETER PollSeconds
    How often to check for new lines.
.NOTES
    Intended to be launched by Deploy-Osquery.ps1 via a Scheduled Task, but
    can be run directly in a console for testing: .\Forward-Osquery.ps1
#>
param(
    [string]$VectorHost = "192.168.10.30",
    [int]$VectorPort = 6007,
    [string]$ResultsLogPath = "C:\ProgramData\osquery\log\osqueryd.results.log",
    [int]$PollSeconds = 5
)

$ErrorActionPreference = "Stop"
$stateFile = "$PSScriptRoot\.last-offset"

function Get-LastOffset {
    if (Test-Path $stateFile) {
        try { return [int64](Get-Content $stateFile -Raw) } catch { return 0 }
    }
    return 0
}

function Set-LastOffset {
    param([int64]$Offset)
    Set-Content -Path $stateFile -Value $Offset
}

function Send-OsqueryLine {
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

Write-Host "SOC Lab osquery forwarder running - shipping to ${VectorHost}:${VectorPort}"

while ($true) {
    try {
        if (Test-Path $ResultsLogPath) {
            $fileInfo = Get-Item $ResultsLogPath
            $lastOffset = Get-LastOffset

            if ($fileInfo.Length -lt $lastOffset) {
                # Log was rotated/truncated - start over from the beginning.
                $lastOffset = 0
            }

            if ($fileInfo.Length -gt $lastOffset) {
                $stream = [System.IO.File]::Open($ResultsLogPath, 'Open', 'Read', 'ReadWrite')
                $stream.Seek($lastOffset, 'Begin') | Out-Null
                $reader = New-Object System.IO.StreamReader($stream)
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($line) { Send-OsqueryLine -Json $line }
                }
                $newOffset = $stream.Position
                $reader.Close()
                $stream.Close()
                Set-LastOffset -Offset $newOffset
            }
        }
    } catch {
        Write-Warning "Poll cycle failed: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $PollSeconds
}
