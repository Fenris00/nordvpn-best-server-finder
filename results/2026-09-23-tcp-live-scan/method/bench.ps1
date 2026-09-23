#requires -version 5.1
# Scratch benchmark (not yet promoted to scripts\). Candidates = gluetun city labels
# (2026-08-06 snapshot) filtered to hosts present in today's official nordcdn bundle.
param(
    [string]$Scratch = $PSScriptRoot,
    [string[]]$Cities = @('Chicago'),
    [int]$Stage2Count = 15,
    [int]$Stage2Pings = 20,
    [int]$Stage2TcpSamples = 10,
    [string]$OutPrefix = 'chicago'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$j = Get-Content "$Scratch\nordvpn-gluetun.json" -Raw | ConvertFrom-Json
$candidates = @($j.servers | Where-Object { $_.vpn -eq 'openvpn' -and $_.tcp -and $_.country -eq 'United States' -and $Cities -contains $_.city })

# Parse remote lines from today's bundle (both TCP variants).
$z = [IO.Compression.ZipFile]::OpenRead("$Scratch\ovpn-fresh.zip")
function Read-Remotes($entryName) {
    $e = $z.GetEntry($entryName)
    if (-not $e) { return $null }
    $r = New-Object IO.StreamReader($e.Open()); $txt = $r.ReadToEnd(); $r.Close()
    $rem = @([regex]::Matches($txt, '(?m)^\s*remote\s+(\S+)\s+(\d+)') | ForEach-Object { [pscustomobject]@{ Host = $_.Groups[1].Value; Port = [int]$_.Groups[2].Value } })
    $comment = ([regex]::Match($txt, '([a-z]{2}\d+\.nordvpn\.com)')).Groups[1].Value
    [pscustomobject]@{ Remotes = $rem; CommentHost = $comment }
}
$targets = New-Object System.Collections.Generic.List[object]
foreach ($c in $candidates) {
    foreach ($variant in 'tcp', 'tcp_2.6') {
        $p = Read-Remotes "ovpn_tcp/$($c.hostname).$variant.ovpn"
        if (-not $p) { continue }
        foreach ($rm in $p.Remotes) {
            $targets.Add([pscustomobject]@{ City = $c.city; Hostname = $c.hostname; Variant = $variant; IP = $rm.Host; Port = $rm.Port; CommentHost = $p.CommentHost })
        }
    }
}
$z.Dispose()
$live = @($targets | Select-Object -ExpandProperty Hostname -Unique)
Write-Host "Candidates (snapshot): $($candidates.Count); present in today's bundle: $($live.Count); endpoint targets: $($targets.Count)"

# Parallel probe via runspace pool.
$probe = {
    param($ip, $port, $pings, $tcpSamples)
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $rtts = @(); $sent = 0
    for ($i = 0; $i -lt $pings; $i++) {
        $sent++
        try { $r = $pinger.Send($ip, 1000); if ($r.Status -eq 'Success') { $rtts += [double]$r.RoundtripTime } } catch {}
    }
    $tcp = @()
    for ($i = 0; $i -lt $tcpSamples; $i++) {
        $cl = New-Object System.Net.Sockets.TcpClient
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $iar = $cl.BeginConnect($ip, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(3000, $false)) { $cl.EndConnect($iar); $sw.Stop(); $tcp += $sw.Elapsed.TotalMilliseconds }
        } catch {} finally { $cl.Close() }
        Start-Sleep -Milliseconds 100
    }
    $jit = $null
    if ($rtts.Count -ge 2) { $d = for ($k = 1; $k -lt $rtts.Count; $k++) { [math]::Abs($rtts[$k] - $rtts[$k - 1]) }; $jit = ($d | Measure-Object -Average).Average }
    $sortedTcp = @($tcp | Sort-Object)
    [pscustomobject]@{
        PingSent = $sent; PingRecv = $rtts.Count
        PingAvg = if ($rtts) { ($rtts | Measure-Object -Average).Average } else { $null }
        PingMin = if ($rtts) { ($rtts | Measure-Object -Minimum).Minimum } else { $null }
        PingMax = if ($rtts) { ($rtts | Measure-Object -Maximum).Maximum } else { $null }
        PingJitter = $jit
        TcpOk = $tcp.Count; TcpTried = $tcpSamples
        TcpMedian = if ($sortedTcp) { $sortedTcp[[int][math]::Floor(($sortedTcp.Count - 1) / 2)] } else { $null }
        TcpMin = if ($sortedTcp) { $sortedTcp[0] } else { $null }
    }
}
function Invoke-Probes($list, $pings, $tcpSamples) {
    $pool = [RunspaceFactory]::CreateRunspacePool(1, 24); $pool.Open()
    $jobs = foreach ($t in $list) {
        $ps = [PowerShell]::Create().AddScript($probe).AddArgument($t.IP).AddArgument($t.Port).AddArgument($pings).AddArgument($tcpSamples)
        $ps.RunspacePool = $pool
        [pscustomobject]@{ T = $t; PS = $ps; H = $ps.BeginInvoke() }
    }
    $out = foreach ($jb in $jobs) {
        $res = $jb.PS.EndInvoke($jb.H)[0]; $jb.PS.Dispose()
        $o = $jb.T.PSObject.Copy()
        foreach ($p in $res.PSObject.Properties) { $o | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
        $o
    }
    $pool.Close(); $out
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
Write-Host "Stage 1 ($stamp): 3 pings + 2 TCP connects per endpoint..."
$s1 = @(Invoke-Probes $targets 3 2)
$s1 | Export-Csv "$Scratch\$OutPrefix-stage1.csv" -NoTypeInformation

# Stage 2: best endpoints by TCP connect (reachable only), one row per host+port.
$best = @($s1 | Where-Object { $_.TcpOk -gt 0 } | Sort-Object TcpMedian, PingAvg | Select-Object -First $Stage2Count)
Write-Host "Stage 1 reachable endpoints: $(@($s1 | Where-Object TcpOk -gt 0).Count) / $($s1.Count). Stage 2 on top $($best.Count)..."
$s2 = @(Invoke-Probes $best $Stage2Pings $Stage2TcpSamples)
$ranked = $s2 | Sort-Object @{e = { - $_.TcpOk } }, TcpMedian, @{e = { if ($null -eq $_.PingAvg) { 1e9 } else { $_.PingAvg } } }
$rank = 0
$final = foreach ($r in $ranked) {
    $rank++
    [pscustomobject]@{
        Rank = $rank; City = $r.City; Hostname = $r.Hostname; IP = $r.IP; Port = $r.Port; Protocol = 'TCP'; Profile = $r.Variant
        AvgLatencyMs = if ($null -ne $r.PingAvg) { [math]::Round($r.PingAvg, 1) } else { 'ICMP filtered' }
        MinMaxMs = if ($null -ne $r.PingAvg) { "$($r.PingMin)/$($r.PingMax)" } else { '' }
        JitterMs = if ($null -ne $r.PingJitter) { [math]::Round($r.PingJitter, 1) } else { '' }
        PacketLossPct = [math]::Round(100 * ($r.PingSent - $r.PingRecv) / $r.PingSent, 1)
        TcpHandshakeMedianMs = if ($null -ne $r.TcpMedian) { [math]::Round($r.TcpMedian, 1) } else { 'fail' }
        TcpSuccess = "$($r.TcpOk)/$($r.TcpTried)"
        Measured = $stamp
    }
}
$final | Export-Csv "$Scratch\$OutPrefix-ranked.csv" -NoTypeInformation
$final | Format-Table -AutoSize | Out-String -Width 250
