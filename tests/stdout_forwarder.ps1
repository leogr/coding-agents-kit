#Requires -Version 5.1
<#
.SYNOPSIS
    Forwards Falco JSON stdout lines to the plugin HTTP server.
    Used on Windows where Falco doesn't have http_output compiled in.

.DESCRIPTION
    Reads a log file that Falco is writing to (stdout redirected to file),
    and POSTs each new JSON line to the specified HTTP endpoint.
    Runs until the specified timeout or until the file stops being written.

.PARAMETER LogFile
    Path to the file Falco stdout is redirected to.

.PARAMETER Url
    HTTP endpoint (e.g. http://127.0.0.1:2802).

.PARAMETER TimeoutSec
    Maximum run time in seconds (default: 60).
#>
param(
    [Parameter(Mandatory)]
    [string]$LogFile,
    [Parameter(Mandatory)]
    [string]$Url,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'SilentlyContinue'
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$position = 0
$remainder = ''

while ((Get-Date) -lt $deadline) {
    if (-not (Test-Path $LogFile)) {
        Start-Sleep -Milliseconds 50
        continue
    }

    try {
        # Open file for shared reading (Falco has it open for writing)
        $fs = [System.IO.File]::Open($LogFile, 'Open', 'Read', 'ReadWrite')
        if ($fs.Length -gt $position) {
            $fs.Position = $position
            $buf = New-Object byte[] ($fs.Length - $position)
            $read = $fs.Read($buf, 0, $buf.Length)
            $position = $fs.Position
            $fs.Close()

            $text = $remainder + [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
            $lines = $text -split "`n"

            # Last element may be incomplete (no trailing newline yet)
            $remainder = $lines[-1]
            $complete = $lines[0..($lines.Length - 2)]

            foreach ($line in $complete) {
                $line = $line.Trim()
                if ($line.Length -eq 0 -or -not $line.StartsWith('{')) { continue }
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
                    $req = [System.Net.HttpWebRequest]::Create($Url)
                    $req.Method = 'POST'
                    $req.ContentType = 'application/json'
                    $req.ContentLength = $bytes.Length
                    $req.Timeout = 2000
                    $s = $req.GetRequestStream()
                    $s.Write($bytes, 0, $bytes.Length)
                    $s.Close()
                    $resp = $req.GetResponse()
                    $resp.Close()
                } catch {}
            }
        } else {
            $fs.Close()
        }
    } catch {}

    Start-Sleep -Milliseconds 20
}
