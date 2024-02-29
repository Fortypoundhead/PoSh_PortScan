$target = "10.0.2.65"
$portRange = 1..1024
$maxJobs = 50 # Maximum concurrent jobs

function Test-Port {
    param ($target, $port)
    $result = Test-NetConnection -ComputerName $target -Port $port -InformationLevel Quiet
    if ($result) {
        return "Port $port is open on $target"
    }
}

$jobs = @()

foreach ($port in $portRange) {
    # If we hit the maximum number of concurrent jobs, wait for one to complete before starting another.
    while (@(Get-Job | Where-Object { $_.State -eq 'Running' }).Count -ge $maxJobs) {
        Start-Sleep -Seconds 1
    }

    $job = Start-Job -ScriptBlock $function:Test-Port -ArgumentList $target, $port
    $jobs += $job
}

# Wait for all jobs to complete
$jobs | Wait-Job

# Gather results and output
$jobs | ForEach-Object {
    $result = Receive-Job -Job $_
    if ($result) {
        Write-Output $result
    }
    Remove-Job -Job $_
}
