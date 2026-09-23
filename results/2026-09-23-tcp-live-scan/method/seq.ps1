param([string]$Scratch = $PSScriptRoot)
# Sequential (non-parallel) re-measure so ICMP rate-limiting doesn't fake packet loss.
function Measure-Tcp($ip, $port, $n) {
    $t = @()
    for ($i = 0; $i -lt $n; $i++) {
        $cl = New-Object System.Net.Sockets.TcpClient; $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $iar = $cl.BeginConnect($ip, $port, $null, $null); if ($iar.AsyncWaitHandle.WaitOne(3000, $false)) { $cl.EndConnect($iar); $t += $sw.Elapsed.TotalMilliseconds } } catch {} finally { $cl.Close() }
        Start-Sleep -Milliseconds 200
    }
    $s = @($t | Sort-Object)
    [pscustomobject]@{ Ok = $s.Count; Median = if ($s) { [math]::Round($s[[int][math]::Floor(($s.Count - 1) / 2)], 1) } else { $null } }
}
$targets = @(
    # Chicago: top endpoints from stage 2 + lowest-ping hosts from stage 1
    @('Chicago','us11571.nordvpn.com','202.49.186.182',1232,'tcp'),
    @('Chicago','us11530.nordvpn.com','193.228.206.170',1233,'tcp'),
    @('Chicago','us11561.nordvpn.com','202.49.186.62',80,'tcp_2.6'),
    @('Chicago','us11536.nordvpn.com','216.183.125.2',1231,'tcp'),
    @('Chicago','us11534.nordvpn.com','193.228.206.218',80,'tcp_2.6'),
    @('Chicago','us11553.nordvpn.com','216.183.125.206',1232,'tcp'),
    @('Chicago','us11575.nordvpn.com','202.49.186.230',1233,'tcp'),
    @('Fargo','us12601.nordvpn.com','216.183.109.2',80,'tcp_2.6'),
    @('Fargo','us12602.nordvpn.com','216.183.109.12',80,'tcp_2.6'),
    @('Fargo','us12603.nordvpn.com','216.183.109.22',80,'tcp_2.6'),
    @('Fargo','us12604.nordvpn.com','216.183.109.32',80,'tcp_2.6'),
    @('Fargo','us12605.nordvpn.com','216.183.109.42',80,'tcp_2.6'),
    @('Fargo','us12601.nordvpn.com','216.183.109.2',1231,'tcp'),
    @('Minneapolis(ref)','us12589.nordvpn.com','216.183.105.2',80,'tcp_2.6'),
    @('SiouxFalls(ref)','us12620.nordvpn.com','216.183.123.2',80,'tcp_2.6')
)
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
$out = foreach ($t in $targets) {
    $o = ping.exe -n 20 -w 1000 $t[2]
    $lost = if (($o -join ' ') -match 'Lost = (\d+)') { [int]$matches[1] } else { 20 }
    $st = if (($o -join ' ') -match 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms') { @($matches[1], $matches[2], $matches[3]) } else { $null }
    $rtts = @($o | Select-String 'time[=<](\d+)ms' | ForEach-Object { [double]$_.Matches[0].Groups[1].Value })
    $jit = if ($rtts.Count -ge 2) { [math]::Round((@(for ($k = 1; $k -lt $rtts.Count; $k++) { [math]::Abs($rtts[$k] - $rtts[$k - 1]) }) | Measure-Object -Average).Average, 1) } else { '' }
    $tcp = Measure-Tcp $t[2] $t[3] 10
    [pscustomobject]@{
        City = $t[0]; Hostname = $t[1]; IP = $t[2]; Port = $t[3]; Protocol = 'TCP'; Profile = $t[4]
        AvgLatencyMs = if ($st) { [int]$st[2] } else { 'ICMP filtered' }; MinMaxMs = if ($st) { "$($st[0])/$($st[1])" } else { '' }; JitterMs = $jit
        PacketLossPct = if ($st) { [math]::Round(100 * $lost / 20) } else { 'n/a (ICMP filtered)' }
        TcpHandshakeMedianMs = $tcp.Median; TcpSuccess = "$($tcp.Ok)/10"; Measured = $stamp
    }
}
$out | Export-Csv "$Scratch\sequential.csv" -NoTypeInformation
$out | Format-Table -AutoSize | Out-String -Width 250
