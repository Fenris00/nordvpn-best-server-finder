[CmdletBinding()]
param(
    [string]$ProfileFolder = ".\ovpn_tcp",
    [string]$LocationCsv = "C:\NordVPN\AllServers.csv",
    [string]$OutputFolder = ".\NordVPN-TCP-Results",
    [int]$PingCount = 2,
    [int]$PingTimeoutMs = 1000,
    [int]$TcpTimeoutMs = 3000,
    [int]$TopN = 30,
    [switch]$IncludeNorthDakotaState
)

$ErrorActionPreference = "Stop"

function Write-Section($text) {
    Write-Host ""
    Write-Host ("=" * 60)
    Write-Host $text
    Write-Host ("=" * 60)
}

function Get-PropertyValue($obj, [string[]]$names) {
    foreach ($n in $names) {
        $p = $obj.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)".Trim() -ne "") {
            return "$($p.Value)".Trim()
        }
    }
    return ""
}

function Normalize-Text($s) {
    if ($null -eq $s) { return "" }
    return (($s -replace '\s+', ' ').Trim())
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return [pscustomobject]@{ Reachable = $false; Ms = $null }
        }
        $client.EndConnect($iar)
        $sw.Stop()
        return [pscustomobject]@{ Reachable = $true; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1) }
    } catch {
        return [pscustomobject]@{ Reachable = $false; Ms = $null }
    } finally {
        $client.Close()
        $client.Dispose()
    }
}

function Test-PingHost {
    param(
        [string]$HostName,
        [int]$Count,
        [int]$TimeoutMs
    )
    try {
        $p = Test-Connection -ComputerName $HostName -Count $Count -ErrorAction SilentlyContinue
        if ($p) {
            $vals = @($p | ForEach-Object { [double]$_.ResponseTime })
            if ($vals.Count -gt 0) {
                return [pscustomobject]@{
                    Success = $true
                    AvgMs = [math]::Round((($vals | Measure-Object -Average).Average), 1)
                    MinMs = [math]::Round((($vals | Measure-Object -Minimum).Minimum), 1)
                    MaxMs = [math]::Round((($vals | Measure-Object -Maximum).Maximum), 1)
                    Replies = $vals.Count
                }
            }
        }
    } catch {}
    return [pscustomobject]@{ Success = $false; AvgMs = $null; MinMs = $null; MaxMs = $null; Replies = 0 }
}

function Parse-OvpnProfile {
    param([string]$Path)

    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    $remoteHost = ""
    $remotePort = 0
    $proto = ""
    $profileType = "Legacy TCP"
    $commentHost = ""

    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t -match '^(?i)remote\s+(\S+)(?:\s+(\d+))?') {
            if (-not $remoteHost) {
                $remoteHost = $matches[1]
                if ($matches[2]) { $remotePort = [int]$matches[2] }
            }
        }
        elseif ($t -match '^(?i)proto\s+(.+)$') {
            $proto = $matches[1].Trim()
        }
        elseif ($t -match '2\.6|data-ciphers|data-cipher') {
            $profileType = "TCP 2.6"
        }

        if (-not $commentHost -and $t -match '([a-z0-9][a-z0-9\-]*\.nordvpn\.com)') {
            $commentHost = $matches[1]
        }
    }

    if ($remotePort -eq 0) {
        # NordVPN TCP profiles commonly use 443, but use the actual profile when present.
        $remotePort = 443
    }

    [pscustomobject]@{
        Path = $Path
        FileName = [IO.Path]::GetFileName($Path)
        Hostname = $remoteHost
        CommentHostname = $commentHost
        Port = $remotePort
        Proto = $proto
        ProfileType = $profileType
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "NORDVPN TCP CHICAGO + FARGO SCANNER V3"
Write-Host "============================================================"
Write-Host "PowerShell version : $($PSVersionTable.PSVersion)"
Write-Host "Profile folder     : $ProfileFolder"
Write-Host "Location CSV       : $LocationCsv"
Write-Host "Output folder      : $OutputFolder"
Write-Host "Ping count         : $PingCount"
Write-Host "Ping timeout       : $PingTimeoutMs ms"
Write-Host "TCP timeout        : $TcpTimeoutMs ms"
Write-Host "Top N              : $TopN"

$ProfileFolder = (Resolve-Path -LiteralPath $ProfileFolder).Path
if (-not (Test-Path -LiteralPath $LocationCsv)) {
    throw "Location CSV not found: $LocationCsv"
}
$OutputFolder = [IO.Path]::GetFullPath($OutputFolder)
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

Write-Section "LOADING LOCAL NORDVPN LOCATION DATABASE"
$locationRows = @(Import-Csv -LiteralPath $LocationCsv)
Write-Host "Location records loaded: $($locationRows.Count)"

if ($locationRows.Count -eq 0) {
    throw "The location CSV is empty."
}

# Build hostname -> location record lookup.
$locationMap = @{}
foreach ($row in $locationRows) {
    $hostName = (Get-PropertyValue $row @("Hostname","hostname","HostName")).ToLowerInvariant()
    if (-not $hostName) { continue }

    $city = Normalize-Text (Get-PropertyValue $row @("FinalCity","City","API1_City","API2_City","API3_City"))
    $state = Normalize-Text (Get-PropertyValue $row @("FinalState","State","API1_State","API2_State","API3_State"))
    $ip = Normalize-Text (Get-PropertyValue $row @("IP","Ip","ip"))
    $confidence = Normalize-Text (Get-PropertyValue $row @("Confidence","confidence"))

    $locationMap[$hostName] = [pscustomobject]@{
        Hostname = $hostName
        IP = $ip
        City = $city
        State = $state
        Confidence = $confidence
    }
}

Write-Section "SCANNING LOCAL TCP .OVPN FILES"
$files = @(Get-ChildItem -LiteralPath $ProfileFolder -Filter "*.ovpn" -File -ErrorAction Stop)
Write-Host "Found $($files.Count) .ovpn files."

Write-Section "PARSING AND MATCHING CHICAGO + FARGO"

$profiles = New-Object System.Collections.Generic.List[object]
$parseFailures = New-Object System.Collections.Generic.List[object]
$matched = New-Object System.Collections.Generic.List[object]
$allNordHosts = New-Object System.Collections.Generic.List[string]
$allRawHosts = New-Object System.Collections.Generic.List[string]

$i = 0
foreach ($f in $files) {
    $i++
    if (($i % 500) -eq 0 -or $i -eq $files.Count) {
        Write-Progress -Activity "Parsing TCP profiles" -Status "$i / $($files.Count)" -PercentComplete (($i / $files.Count) * 100)
    }

    try {
        $p = Parse-OvpnProfile -Path $f.FullName
        if (-not $p.Hostname) {
            $parseFailures.Add([pscustomobject]@{ FileName=$f.Name; Path=$f.FullName; Reason="No remote hostname found" })
            continue
        }

        $hostName = $p.Hostname.ToLowerInvariant()
        $allRawHosts.Add($hostName)
        if ($hostName -notmatch 'nordvpn\.com$') {
            if ($p.CommentHostname) {
                # 'remote' line was an IP address; fall back to a hostname found in a comment line.
                $hostName = $p.CommentHostname.ToLowerInvariant()
            } else {
                continue
            }
        }
        $allNordHosts.Add($hostName)

        $loc = $null
        if ($locationMap.ContainsKey($hostName)) {
            $loc = $locationMap[$hostName]
        }

        if ($loc) {
            $city = $loc.City
            $state = $loc.State
            $isChicago = ($city -match '(?i)^chicago$')
            $isFargo = ($city -match '(?i)^fargo$')
            if (-not $isFargo -and $IncludeNorthDakotaState) {
                $isFargo = ($state -match '(?i)North Dakota|ND')
            }

            if ($isChicago -or $isFargo) {
                $matched.Add([pscustomobject]@{
                    Region = if ($isChicago) { "Chicago" } else { "Fargo" }
                    Hostname = $hostName
                    IP = $loc.IP
                    City = $city
                    State = $state
                    Confidence = $loc.Confidence
                    FileName = $p.FileName
                    ProfilePath = $p.Path
                    Port = $p.Port
                    Proto = $p.Proto
                    ProfileType = $p.ProfileType
                })
            }
        }
    } catch {
        $parseFailures.Add([pscustomobject]@{ FileName=$f.Name; Path=$f.FullName; Reason=$_.Exception.Message })
    }
}
Write-Progress -Activity "Parsing TCP profiles" -Completed

$chiCount = @($matched | Where-Object Region -eq "Chicago").Count
$fargoCount = @($matched | Where-Object Region -eq "Fargo").Count
Write-Host "Chicago matched profiles : $chiCount"
Write-Host "Fargo matched profiles   : $fargoCount"
Write-Host "Total matched profiles   : $($matched.Count)"

if ($matched.Count -eq 0) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    $parseFailures | Export-Csv (Join-Path $OutputFolder "Profile-Parse-Failures.csv") -NoTypeInformation -Encoding UTF8

    Write-Section "DIAGNOSTICS: WHY 0 MATCHES?"

    $uniqueNordHosts = @($allNordHosts | Select-Object -Unique)
    $uniqueRawHosts = @($allRawHosts | Select-Object -Unique)
    Write-Host "Unique raw 'remote' values found in .ovpn files      : $($uniqueRawHosts.Count)"
    Write-Host "Unique *.nordvpn.com hostnames found (incl. comment fallback) : $($uniqueNordHosts.Count)"
    Write-Host "Unique hostnames loaded from location CSV            : $($locationMap.Keys.Count)"

    Write-Host ""
    Write-Host "Sample RAW 'remote' values parsed from .ovpn files (first 5):"
    $uniqueRawHosts | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "Sample hostnames parsed FROM .ovpn FILES (first 5):"
    $uniqueNordHosts | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "Sample hostnames loaded FROM CSV (first 5):"
    $locationMap.Keys | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }

    $hostsInMap = @($uniqueNordHosts | Where-Object { $locationMap.ContainsKey($_) })
    Write-Host ""
    Write-Host "Ovpn hostnames that DO exist in the CSV (any city)   : $($hostsInMap.Count) / $($uniqueNordHosts.Count)"

    if ($hostsInMap.Count -gt 0) {
        Write-Host ""
        Write-Host "Distinct City values for those matched hostnames:"
        $hostsInMap | ForEach-Object { $locationMap[$_].City } | Where-Object { $_ } | Select-Object -Unique | Sort-Object | ForEach-Object { Write-Host "  '$_'" }
        Write-Host ""
        Write-Host "Distinct State values for those matched hostnames:"
        $hostsInMap | ForEach-Object { $locationMap[$_].State } | Where-Object { $_ } | Select-Object -Unique | Sort-Object | ForEach-Object { Write-Host "  '$_'" }
    } else {
        Write-Host ""
        Write-Host "NONE of your .ovpn hostnames were found as keys in the CSV at all." -ForegroundColor Yellow
        Write-Host "This means the Hostname/hostname/HostName column in AllServers.csv" -ForegroundColor Yellow
        Write-Host "does not match the 'remote <host>' values inside your .ovpn files" -ForegroundColor Yellow
        Write-Host "(check for a different domain suffix, subdomain format, or wrong column)." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "All distinct City values present anywhere in the CSV (first 30):"
    $locationRows | ForEach-Object { Get-PropertyValue $_ @("FinalCity","City","API1_City","API2_City","API3_City") } | Where-Object { $_ } | Select-Object -Unique | Sort-Object | Select-Object -First 30 | ForEach-Object { Write-Host "  '$_'" }

    Write-Host ""
    Write-Host "All distinct State values present anywhere in the CSV (first 30):"
    $locationRows | ForEach-Object { Get-PropertyValue $_ @("FinalState","State","API1_State","API2_State","API3_State") } | Where-Object { $_ } | Select-Object -Unique | Sort-Object | Select-Object -First 30 | ForEach-Object { Write-Host "  '$_'" }

    Write-Host ""
    Write-Host "Hostnames listed in the CSV specifically for Chicago:"
    $chicagoCsvHosts = @($locationMap.Values | Where-Object { $_.City -match '(?i)^chicago$' } | ForEach-Object { $_.Hostname })
    if ($chicagoCsvHosts.Count -eq 0) {
        Write-Host "  (none - the CSV has no rows where City = 'Chicago')"
    } else {
        $chicagoCsvHosts | ForEach-Object {
            $inLocalFiles = $uniqueNordHosts -contains $_
            Write-Host "  $_  -- present in your local .ovpn files: $inLocalFiles"
        }
    }

    Write-Host ""
    Write-Host "Hostnames listed in the CSV specifically for Fargo / North Dakota:"
    $fargoCsvHosts = @($locationMap.Values | Where-Object { $_.City -match '(?i)^fargo$' -or $_.State -match '(?i)North Dakota|^ND$' } | ForEach-Object { $_.Hostname })
    if ($fargoCsvHosts.Count -eq 0) {
        Write-Host "  (none - the CSV has no rows for Fargo or North Dakota at all)"
    } else {
        $fargoCsvHosts | ForEach-Object {
            $inLocalFiles = $uniqueNordHosts -contains $_
            Write-Host "  $_  -- present in your local .ovpn files: $inLocalFiles"
        }
    }

    throw "No Chicago/Fargo TCP profiles matched AllServers.csv. See diagnostics above to see whether hostnames or city names failed to match."
}

# Deduplicate testing: multiple profiles may point to the same hostname/port.
$uniqueTargets = @($matched | Group-Object Hostname, Port | ForEach-Object { $_.Group[0] })
Write-Host "Unique server targets to test: $($uniqueTargets.Count)"

Write-Section "PINGING + TESTING ACTUAL TCP OPENVPN PORT"

$results = New-Object System.Collections.Generic.List[object]
$idx = 0

foreach ($target in $uniqueTargets) {
    $idx++
    Write-Progress -Activity "Testing Chicago/Fargo TCP servers" `
        -Status "$idx / $($uniqueTargets.Count) : $($target.Hostname):$($target.Port)" `
        -PercentComplete (($idx / $uniqueTargets.Count) * 100)

    $ping = Test-PingHost -HostName $target.Hostname -Count $PingCount -TimeoutMs $PingTimeoutMs
    $tcp = Test-TcpPort -HostName $target.Hostname -Port $target.Port -TimeoutMs $TcpTimeoutMs

    $serverProfiles = @($matched | Where-Object { $_.Hostname -eq $target.Hostname -and $_.Port -eq $target.Port })

    foreach ($sp in $serverProfiles) {
        $results.Add([pscustomobject]@{
            Region = $sp.Region
            Hostname = $sp.Hostname
            IP = $sp.IP
            City = $sp.City
            State = $sp.State
            GeoConfidence = $sp.Confidence
            Port = $sp.Port
            Proto = $sp.Proto
            ProfileType = $sp.ProfileType
            PingOK = $ping.Success
            PingAvgMs = $ping.AvgMs
            PingMinMs = $ping.MinMs
            PingMaxMs = $ping.MaxMs
            PingReplies = $ping.Replies
            TcpOK = $tcp.Reachable
            TcpConnectMs = $tcp.Ms
            ProfileFile = $sp.FileName
            ProfilePath = $sp.ProfilePath
        })
    }
}
Write-Progress -Activity "Testing Chicago/Fargo TCP servers" -Completed

# Ranking: TCP reachability first, then ping, then TCP connect time.
$ranked = @(
    $results |
    Sort-Object `
        @{Expression={ if ($_.TcpOK) { 0 } else { 1 } }}, `
        @{Expression={ if ($null -eq $_.PingAvgMs) { [double]::PositiveInfinity } else { $_.PingAvgMs } }}, `
        @{Expression={ if ($null -eq $_.TcpConnectMs) { [double]::PositiveInfinity } else { $_.TcpConnectMs } }}, `
        @{Expression={ if ($_.ProfileType -eq "TCP 2.6") { 0 } else { 1 } }}
)

# Add a simple human-readable rank after sorting.
$rankedWithRank = New-Object System.Collections.Generic.List[object]
$r = 0
foreach ($x in $ranked) {
    $r++
    $rankedWithRank.Add([pscustomobject]@{
        Rank = $r
        Region = $x.Region
        Hostname = $x.Hostname
        IP = $x.IP
        Port = $x.Port
        ProfileType = $x.ProfileType
        PingOK = $x.PingOK
        PingAvgMs = $x.PingAvgMs
        PingMinMs = $x.PingMinMs
        PingMaxMs = $x.PingMaxMs
        TcpOK = $x.TcpOK
        TcpConnectMs = $x.TcpConnectMs
        GeoConfidence = $x.GeoConfidence
        ProfileFile = $x.ProfileFile
        ProfilePath = $x.ProfilePath
    })
}

Write-Section "SAVING RESULTS"

$allCsv = Join-Path $OutputFolder "All-Chicago-Fargo-TCP.csv"
$chiCsv = Join-Path $OutputFolder "Chicago-TCP.csv"
$fargoCsv = Join-Path $OutputFolder "Fargo-TCP.csv"
$topCsv = Join-Path $OutputFolder "Top-TCP-Servers.csv"
$readyCsv = Join-Path $OutputFolder "Top-TCP-Ready-for-pfSense.csv"
$pathsTxt = Join-Path $OutputFolder "Top-TCP-Profile-Paths.txt"
$summaryTxt = Join-Path $OutputFolder "TCP-Scan-Summary.txt"
$failCsv = Join-Path $OutputFolder "Profile-Parse-Failures.csv"

$rankedWithRank | Export-Csv $allCsv -NoTypeInformation -Encoding UTF8
@($rankedWithRank | Where-Object Region -eq "Chicago") | Export-Csv $chiCsv -NoTypeInformation -Encoding UTF8
@($rankedWithRank | Where-Object Region -eq "Fargo") | Export-Csv $fargoCsv -NoTypeInformation -Encoding UTF8
@($rankedWithRank | Select-Object -First $TopN) | Export-Csv $topCsv -NoTypeInformation -Encoding UTF8

$ready = @(
    $rankedWithRank |
    Where-Object { $_.TcpOK -eq $true } |
    Select-Object -First $TopN
)
$ready | Export-Csv $readyCsv -NoTypeInformation -Encoding UTF8
$ready | ForEach-Object { $_.ProfilePath } | Set-Content -LiteralPath $pathsTxt -Encoding UTF8
$parseFailures | Export-Csv $failCsv -NoTypeInformation -Encoding UTF8

$summary = @()
$summary += "NordVPN TCP Chicago + Fargo Scanner V3"
$summary += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$summary += "Profile folder: $ProfileFolder"
$summary += "Location CSV: $LocationCsv"
$summary += "Profiles found: $($files.Count)"
$summary += "Chicago matched profiles: $chiCount"
$summary += "Fargo matched profiles: $fargoCount"
$summary += "Unique server targets tested: $($uniqueTargets.Count)"
$summary += "TCP-reachable profiles: $(@($rankedWithRank | Where-Object TcpOK).Count)"
$summary += ""
$summary += "Top results:"
foreach ($x in @($rankedWithRank | Select-Object -First $TopN)) {
    $summary += ("#{0} [{1}] {2}:{3} | Ping={4}ms | TCP={5} ({6}ms) | {7} | {8}" -f `
        $x.Rank,$x.Region,$x.Hostname,$x.Port,$x.PingAvgMs,$x.TcpOK,$x.TcpConnectMs,$x.ProfileType,$x.ProfileFile)
}
$summary | Set-Content -LiteralPath $summaryTxt -Encoding UTF8

Write-Section "TOP $TopN TCP SERVERS"

$display = @($rankedWithRank | Select-Object -First $TopN Rank,Region,Hostname,Port,ProfileType,PingAvgMs,TcpOK,TcpConnectMs,GeoConfidence,ProfileFile)
$display | Format-Table -AutoSize

Write-Host ""
Write-Host "============================================================"
Write-Host "OUTPUT FILES"
Write-Host "============================================================"
Write-Host "All results       : $allCsv"
Write-Host "Chicago            : $chiCsv"
Write-Host "Fargo              : $fargoCsv"
Write-Host "Top $TopN           : $topCsv"
Write-Host "TCP-ready profiles : $readyCsv"
Write-Host "Exact profile paths: $pathsTxt"
Write-Host "Summary            : $summaryTxt"
Write-Host "Parse failures     : $failCsv"
Write-Host ""
Write-Host "IMPORTANT: Geo location comes from AllServers.csv and is an IP-geolocation estimate."
Write-Host "TCP OK means the server's advertised TCP endpoint accepted a TCP connection."
Write-Host "A TCP port test does NOT prove that the complete OpenVPN authentication succeeded."
Write-Host "For pfSense, verify the selected profile actually reaches 'Initialization Sequence Completed'."
Write-Host ""
