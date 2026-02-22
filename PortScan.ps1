<#
.SYNOPSIS
    Fast, concurrent TCP port scanner for Windows PowerShell 5.1.

.DESCRIPTION
    Invoke-PortScan performs a TCP connect scan against one or more target hosts using
    lightweight runspaces (not Start-Job) for high performance and low overhead.

    Optional features:
      - Reverse DNS resolution (-ResolveDns)
      - Service guessing by port (-ServiceGuess)
      - Per-port timing in milliseconds (-IncludeTiming)
      - Final summary object with total duration (-IncludeSummary)

.NOTES
    Requires: Windows PowerShell 5.1
    Scan type: TCP connect (not SYN). Connection attempts may be logged by firewalls/IDS.

.EXAMPLE
    Invoke-PortScan -ComputerName 10.0.2.65 -StartPort 1 -EndPort 1024 -OpenOnly -ServiceGuess -IncludeTiming

.EXAMPLE
    '10.0.2.65','10.0.2.66' |
      Invoke-PortScan -Port 22,80,443,3389 -ResolveDns -ServiceGuess -IncludeTiming -IncludeSummary |
      Sort-Object ComputerName,Port
#>
function Invoke-PortScan {
    [CmdletBinding(DefaultParameterSetName = 'Range')]
    param(
        # Target host(s): IP or DNS name
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Target','Host','Name','IPAddress','IP')]
        [string[]] $ComputerName,

        # Explicit port list
        [Parameter(Mandatory, ParameterSetName = 'List')]
        [ValidateRange(1, 65535)]
        [int[]] $Port,

        # Port range (inclusive)
        [Parameter(Mandatory, ParameterSetName = 'Range')]
        [ValidateRange(1, 65535)]
        [int] $StartPort,

        [Parameter(Mandatory, ParameterSetName = 'Range')]
        [ValidateRange(1, 65535)]
        [int] $EndPort,

        # TCP connect timeout per port (ms)
        [ValidateRange(1, 60000)]
        [int] $TimeoutMs = 300,

        # Maximum concurrent runspaces
        [ValidateRange(1, 2000)]
        [int] $ThrottleLimit = 200,

        # Emit only open ports
        [switch] $OpenOnly,

        # Perform reverse DNS lookup (only once per host)
        [switch] $ResolveDns,

        # Add a best-effort service name guess (based on port)
        [switch] $ServiceGuess,

        # Include per-port elapsed time in milliseconds (TimeMs)
        [switch] $IncludeTiming,

        # Suppress Write-Progress output
        [switch] $NoProgress,

        # Emit a final summary object with elapsed time
        [switch] $IncludeSummary
    )

    begin {
        # Collect pipeline targets
        $targets = New-Object System.Collections.Generic.List[string]

        # Build final port list once
        $portsToScan = switch ($PSCmdlet.ParameterSetName) {
            'List'  { $Port }
            'Range' {
                if ($EndPort -lt $StartPort) {
                    throw "EndPort ($EndPort) must be >= StartPort ($StartPort)."
                }
                $StartPort..$EndPort
            }
        }

        # Overall scan timer
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Best-effort port -> service map (expand anytime)
        $serviceMap = @{
            20   = 'FTP-Data'
            21   = 'FTP'
            22   = 'SSH'
            23   = 'Telnet'
            25   = 'SMTP'
            53   = 'DNS'
            67   = 'DHCP-Server'
            68   = 'DHCP-Client'
            69   = 'TFTP'
            80   = 'HTTP'
            88   = 'Kerberos'
            110  = 'POP3'
            123  = 'NTP'
            135  = 'RPC'
            137  = 'NetBIOS-NS'
            138  = 'NetBIOS-DGM'
            139  = 'NetBIOS-SSN'
            143  = 'IMAP'
            389  = 'LDAP'
            443  = 'HTTPS'
            445  = 'SMB'
            465  = 'SMTPS'
            587  = 'SMTP-Submission'
            636  = 'LDAPS'
            993  = 'IMAPS'
            995  = 'POP3S'
            1433 = 'MSSQL'
            1521 = 'Oracle'
            2049 = 'NFS'
            3306 = 'MySQL'
            3389 = 'RDP'
            5432 = 'PostgreSQL'
            5985 = 'WinRM-HTTP'
            5986 = 'WinRM-HTTPS'
            6379 = 'Redis'
            8080 = 'HTTP-Alt'
            8443 = 'HTTPS-Alt'
        }

        # Scriptblock executed inside each runspace
        # Uses TcpClient for controllable timeout behavior, with optional per-port timing
        $scanScript = {
            param(
                [string] $ComputerName,
                [int]    $Port,
                [int]    $TimeoutMs,
                [bool]   $IncludeTiming
            )

            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $null
            $t = $null

            if ($IncludeTiming) {
                $t = [System.Diagnostics.Stopwatch]::StartNew()
            }

            try {
                $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)

                if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                    if ($IncludeTiming) { $t.Stop() }
                    return [pscustomobject]@{
                        ComputerName = $ComputerName
                        Port         = $Port
                        Open         = $false
                        Reason       = 'Timeout'
                        TimeoutMs    = $TimeoutMs
                        TimeMs       = if ($IncludeTiming) { [math]::Round($t.Elapsed.TotalMilliseconds, 2) } else { $null }
                    }
                }

                $client.EndConnect($iar) | Out-Null

                if ($IncludeTiming) { $t.Stop() }
                return [pscustomobject]@{
                    ComputerName = $ComputerName
                    Port         = $Port
                    Open         = $true
                    Reason       = $null
                    TimeoutMs    = $TimeoutMs
                    TimeMs       = if ($IncludeTiming) { [math]::Round($t.Elapsed.TotalMilliseconds, 2) } else { $null }
                }
            }
            catch {
                if ($IncludeTiming -and $t) { $t.Stop() }
                return [pscustomobject]@{
                    ComputerName = $ComputerName
                    Port         = $Port
                    Open         = $false
                    Reason       = $_.Exception.Message
                    TimeoutMs    = $TimeoutMs
                    TimeMs       = if ($IncludeTiming -and $t) { [math]::Round($t.Elapsed.TotalMilliseconds, 2) } else { $null }
                }
            }
            finally {
                try { $client.Close() } catch {}
                if ($iar -and $iar.AsyncWaitHandle) { try { $iar.AsyncWaitHandle.Close() } catch {} }
            }
        }

        # Create runspace pool (lightweight threads)
        $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
        $pool.Open()

        # DNS lookup cache (avoid repeated reverse lookups)
        $dnsCache = @{}
    }

    process {
        foreach ($cn in $ComputerName) {
            if (-not [string]::IsNullOrWhiteSpace($cn)) {
                $targets.Add($cn) | Out-Null
            }
        }
    }

    end {
        $workItems = New-Object System.Collections.Generic.List[object]
        $totalChecks = $targets.Count * $portsToScan.Count
        $queued = 0

        # Queue all scan work
        foreach ($target in $targets) {
            foreach ($p in $portsToScan) {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $pool

                # Add script + args positionally (avoids prompting issues)
                [void]$ps.AddScript($scanScript).
                          AddArgument($target).
                          AddArgument($p).
                          AddArgument($TimeoutMs).
                          AddArgument([bool]$IncludeTiming)

                $handle = $ps.BeginInvoke()

                $workItems.Add([pscustomobject]@{
                    PS     = $ps
                    Handle = $handle
                }) | Out-Null

                $queued++
                if (-not $NoProgress -and ($queued % 256 -eq 0 -or $queued -eq $totalChecks)) {
                    Write-Progress -Activity "Port scan" -Status "Queued $queued of $totalChecks" -PercentComplete ([int](($queued / $totalChecks) * 100))
                }
            }
        }

        # Collect results
        $completed = 0
        foreach ($item in $workItems) {
            try {
                $results = $item.PS.EndInvoke($item.Handle)

                foreach ($r in $results) {
                    if ($OpenOnly -and -not $r.Open) { continue }

                    # Optional reverse DNS resolution (cached per target)
                    if ($ResolveDns) {
                        $key = $r.ComputerName.ToLowerInvariant()
                        if (-not $dnsCache.ContainsKey($key)) {
                            try { $dnsCache[$key] = [System.Net.Dns]::GetHostEntry($r.ComputerName).HostName }
                            catch { $dnsCache[$key] = $null }
                        }
                        $r | Add-Member -NotePropertyName HostName -NotePropertyValue $dnsCache[$key] -Force
                    }

                    # Optional service name guess (cheap and handy)
                    if ($ServiceGuess) {
                        $svc = $null
                        if ($serviceMap.ContainsKey([int]$r.Port)) { $svc = $serviceMap[[int]$r.Port] }
                        $r | Add-Member -NotePropertyName Service -NotePropertyValue $svc -Force
                    }

                    # If timing is not requested, remove TimeMs for cleaner output
                    if (-not $IncludeTiming) {
                        # (TimeMs already exists but will be $null; removing keeps objects tidy)
                        if ($r.PSObject.Properties.Match('TimeMs').Count -gt 0) {
                            $r.PSObject.Properties.Remove('TimeMs') | Out-Null
                        }
                    }

                    $r
                }
            }
            finally {
                $item.PS.Dispose()
                $completed++
                if (-not $NoProgress -and ($completed % 256 -eq 0 -or $completed -eq $totalChecks)) {
                    Write-Progress -Activity "Port scan" -Status "Completed $completed of $totalChecks" -PercentComplete ([int](($completed / $totalChecks) * 100))
                }
            }
        }

        if (-not $NoProgress) { Write-Progress -Activity "Port scan" -Completed }

        # Tear down runspace pool
        $pool.Close()
        $pool.Dispose()

        # Stop overall timer and optionally emit summary
        $stopwatch.Stop()
        $elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)

        if ($IncludeSummary) {
            [pscustomobject]@{
                ComputerCount = $targets.Count
                PortCount     = $portsToScan.Count
                TotalChecks   = $totalChecks
                TimeoutMs     = $TimeoutMs
                ThrottleLimit = $ThrottleLimit
                ResolveDns    = [bool]$ResolveDns
                ServiceGuess  = [bool]$ServiceGuess
                IncludeTiming = [bool]$IncludeTiming
                ScanSeconds   = $elapsedSeconds
                Message       = "Scan completed in $elapsedSeconds seconds"
            }
        }
        else {
            Write-Verbose "Scan completed in $elapsedSeconds seconds"
        }
    }
}
