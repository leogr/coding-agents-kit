#Requires -Version 5.1
<#
.SYNOPSIS
    TCP mock broker for testing the interceptor on Windows.

.PARAMETER Port
    Port to listen on (0 for auto-assign).

.PARAMETER Mode
    Response mode: allow, deny, ask, slow:<seconds>, close, bad_json, wrong_id
#>
param(
    [int]$Port = 0,
    [string]$Mode = 'allow'
)

$ErrorActionPreference = 'Stop'

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
$actualPort = $listener.LocalEndpoint.Port

# Signal readiness
[Console]::Out.WriteLine("READY:$actualPort")
[Console]::Out.Flush()

try {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()

    # Read request (newline-terminated JSON)
    $buffer = New-Object byte[] 131072
    $data = ''
    while (-not $data.Contains("`n")) {
        $stream.ReadTimeout = 5000
        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
        if ($bytesRead -eq 0) { break }
        $data += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
    }

    if ($Mode -eq 'close') {
        $client.Close()
        return
    }

    # Parse request ID
    $reqId = 'unknown'
    try {
        $req = $data.Trim() | ConvertFrom-Json
        if ($req.id) { $reqId = $req.id }
    } catch {}

    # Build response
    $resp = $null
    switch -Wildcard ($Mode) {
        'deny' {
            $resp = @{ id = $reqId; decision = 'deny'; reason = 'blocked by test rule' }
        }
        'ask' {
            $resp = @{ id = $reqId; decision = 'ask'; reason = 'requires confirmation' }
        }
        'bad_json' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("this is not json`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $client.Close()
            return
        }
        'wrong_id' {
            $resp = @{ id = 'wrong-id-xxx'; decision = 'allow'; reason = '' }
        }
        'slow:*' {
            $delay = [double]($Mode -split ':')[1]
            Start-Sleep -Milliseconds ([int]($delay * 1000))
            $resp = @{ id = $reqId; decision = 'allow'; reason = '' }
        }
        default {
            $resp = @{ id = $reqId; decision = 'allow'; reason = '' }
        }
    }

    if ($resp) {
        $json = ($resp | ConvertTo-Json -Compress) + "`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
    }

    $client.Close()
}
finally {
    $listener.Stop()
}
