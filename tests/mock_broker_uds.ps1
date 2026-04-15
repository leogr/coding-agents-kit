#Requires -Version 5.1
<#
.SYNOPSIS
    Unix domain socket mock broker for testing the interceptor on Windows.
    Uses PowerShell 7's UnixDomainSocketEndPoint if available, otherwise
    falls back to raw Winsock2 via P/Invoke.

.PARAMETER SocketPath
    Path for the Unix domain socket file.

.PARAMETER Mode
    Response mode: allow, deny, ask, slow:<seconds>, close, bad_json, wrong_id
#>
param(
    [Parameter(Mandatory)]
    [string]$SocketPath,
    [string]$Mode = 'allow'
)

$ErrorActionPreference = 'Stop'

# Remove stale socket
if (Test-Path $SocketPath) { Remove-Item $SocketPath -Force }
$parent = Split-Path $SocketPath -Parent
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

# P/Invoke for AF_UNIX sockets on Windows
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WinSock {
    public const int AF_UNIX = 1;
    public const int SOCK_STREAM = 1;
    public const int IPPROTO_TCP = 0;
    public const int INVALID_SOCKET = -1;

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_un {
        public ushort sun_family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 108)]
        public byte[] sun_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WSAData {
        public short wVersion;
        public short wHighVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
    }

    [DllImport("ws2_32.dll")] public static extern int WSAStartup(short version, out WSAData data);
    [DllImport("ws2_32.dll")] public static extern int WSACleanup();
    [DllImport("ws2_32.dll")] public static extern IntPtr socket(int af, int type, int protocol);
    [DllImport("ws2_32.dll")] public static extern int bind(IntPtr s, ref sockaddr_un addr, int namelen);
    [DllImport("ws2_32.dll")] public static extern int listen(IntPtr s, int backlog);
    [DllImport("ws2_32.dll")] public static extern IntPtr accept(IntPtr s, IntPtr addr, IntPtr addrlen);
    [DllImport("ws2_32.dll")] public static extern int recv(IntPtr s, byte[] buf, int len, int flags);
    [DllImport("ws2_32.dll")] public static extern int send(IntPtr s, byte[] buf, int len, int flags);
    [DllImport("ws2_32.dll")] public static extern int closesocket(IntPtr s);
    [DllImport("ws2_32.dll")] public static extern int WSAGetLastError();

    public static sockaddr_un MakeAddr(string path) {
        var addr = new sockaddr_un();
        addr.sun_family = AF_UNIX;
        addr.sun_path = new byte[108];
        byte[] pathBytes = Encoding.UTF8.GetBytes(path);
        Array.Copy(pathBytes, addr.sun_path, Math.Min(pathBytes.Length, 107));
        return addr;
    }
}
"@

# Initialize Winsock
$wsaData = New-Object WinSock+WSAData
[void][WinSock]::WSAStartup(0x0202, [ref]$wsaData)

$serverSock = [WinSock]::socket([WinSock]::AF_UNIX, [WinSock]::SOCK_STREAM, 0)
$addr = [WinSock]::MakeAddr($SocketPath)
$addrSize = [System.Runtime.InteropServices.Marshal]::SizeOf($addr)

$bindResult = [WinSock]::bind($serverSock, [ref]$addr, $addrSize)
if ($bindResult -ne 0) {
    $err = [WinSock]::WSAGetLastError()
    throw "bind failed: WSA error $err"
}

[void][WinSock]::listen($serverSock, 1)

# Signal readiness
[Console]::Out.WriteLine("READY:$SocketPath")
[Console]::Out.Flush()

try {
    $clientSock = [WinSock]::accept($serverSock, [IntPtr]::Zero, [IntPtr]::Zero)

    # Read request
    $buffer = New-Object byte[] 131072
    $data = ''
    while (-not $data.Contains("`n")) {
        $n = [WinSock]::recv($clientSock, $buffer, $buffer.Length, 0)
        if ($n -le 0) { break }
        $data += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $n)
    }

    if ($Mode -eq 'close') {
        [void][WinSock]::closesocket($clientSock)
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
        'deny'     { $resp = @{ id = $reqId; decision = 'deny'; reason = 'blocked by test rule' } }
        'ask'      { $resp = @{ id = $reqId; decision = 'ask'; reason = 'requires confirmation' } }
        'bad_json' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("this is not json`n")
            [void][WinSock]::send($clientSock, $bytes, $bytes.Length, 0)
            [void][WinSock]::closesocket($clientSock)
            return
        }
        'wrong_id' { $resp = @{ id = 'wrong-id-xxx'; decision = 'allow'; reason = '' } }
        'slow:*' {
            $delay = [double]($Mode -split ':')[1]
            Start-Sleep -Milliseconds ([int]($delay * 1000))
            $resp = @{ id = $reqId; decision = 'allow'; reason = '' }
        }
        default    { $resp = @{ id = $reqId; decision = 'allow'; reason = '' } }
    }

    if ($resp) {
        $json = ($resp | ConvertTo-Json -Compress) + "`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        [void][WinSock]::send($clientSock, $bytes, $bytes.Length, 0)
    }

    [void][WinSock]::closesocket($clientSock)
}
finally {
    [void][WinSock]::closesocket($serverSock)
    [void][WinSock]::WSACleanup()
    Remove-Item $SocketPath -Force -ErrorAction SilentlyContinue
}
