# Invoke-PortScan (PowerShell 5.1)

A fast, lightweight TCP port scanner written in pure PowerShell, designed for real-world Windows administration and troubleshooting.

This script uses runspaces (not Start-Job) to efficiently scan ports with configurable concurrency, timeouts, service guessing, DNS resolution, and per-port timing — all while remaining fully compatible with Windows PowerShell 5.1.

This is not meant to replace tools like nmap. It is meant to be the tool you actually reach for during day-to-day diagnostics.

## Features

- ⚡ Fast concurrent scanning using runspace pools
- 🧵 Configurable throttle limit (no runaway job storms)
- ⏱ Per-port TCP timeout control
- 📊 Object-based output (pipeline friendly)
- 🌐 Optional reverse DNS resolution
- 🔍 Optional service name guessing (SSH, HTTP, RDP, SMB, etc.)
- 🕒 Optional per-port timing (milliseconds)
- 🧾 Optional scan summary with total runtime
- ✅ Works in Windows PowerShell 5.1 (no PS7 required)

## Requirements

- Windows PowerShell 5.1
- .NET Framework (default on modern Windows)
-  Network access to target hosts

No external modules or binaries required.

## Installation

Clone or download the repository, then dot-source the script or load it into your session:

`. .\Invoke-PortScan.ps1`

You can also place it in one of your PowerShell profile or tools directories.

## Basic Usage

Scan specific ports on a single host:

`Invoke-PortScan -ComputerName 10.0.2.65 -Port 22,80,443`

Scan a port range and show only open ports:

`Invoke-PortScan -ComputerName 10.0.2.65 -StartPort 1 -EndPort 1024 -OpenOnly`

Scan multiple hosts from the pipeline:

`'10.0.2.65','10.0.2.66' | Invoke-PortScan -Port 445,3389,5985`

## Optional Enhancements

### Resolve DNS names

Adds a HostName property (cached per host):

`Invoke-PortScan -ComputerName 10.0.2.65 -Port 3389 -ResolveDns`

### Guess common services by port

Adds a Service property (best effort):

`Invoke-PortScan -ComputerName 10.0.2.65 -Port 22,80,443 -ServiceGuess`

### Measure timing per port

Adds a TimeMs property:

`Invoke-PortScan -ComputerName 10.0.2.65 -StartPort 1 -EndPort 1024 -IncludeTiming`

### Emit a scan summary

Outputs a final summary object with total runtime:

`Invoke-PortScan -ComputerName 10.0.2.65 -Port 22,80,443 -IncludeSummary`

## Exporting Results

Because the output is object-based, exporting is trivial:

```
Invoke-PortScan -ComputerName server01 -StartPort 1 -EndPort 1024 |
  Where-Object Open |
  Export-Csv .\OpenPorts.csv -NoTypeInformation
```

## Output Properties

Depending on switches used, results may include:

- ComputerName
- HostName (with -ResolveDns)
- Port
- Open
- Service (with -ServiceGuess)
- TimeMs (with -IncludeTiming)
- Reason
- TimeoutMs

## Important Notes

- This performs a TCP connect scan, not a SYN or stealth scan.
- Firewalls and IDS/IPS systems may log connection attempts.
- Intended for administrative diagnostics, not evasion or offensive scanning.

## Why Runspaces Instead of Start-Job?

Start-Job spins up a full PowerShell process per job — expensive and slow at scale. Runspaces are lightweight threads inside the same process, which makes this scanner:

- Faster
- More memory-efficient
- Easier to throttle safely

This matters when scanning hundreds or thousands of ports.

## License

MIT License
Use it, modify it, break it, improve it.

## Contributions

Issues, improvements, and pull requests are welcome — especially:

- Additional service mappings
- Output formatting ideas
- Performance tuning suggestions
