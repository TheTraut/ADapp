#Requires -Version 5.1

<#
.SYNOPSIS
    UserLocationIndex module for tracking and querying user logon locations.
.DESCRIPTION
    Provides functions to initialize, update, and query a centralized user
    location index built from per-computer UserLogon.csv files and live
    quser lookups.  The module maintains a local CentralizedUserLogon.csv
    database, supports background job-based scanning of AD computers, and
    exposes WinForms-based viewer dialogs.
.NOTES
    Module : UserLocationIndex
    Author : ADapp Team
#>

#region Functions

function Initialize-UserLocationIndex {
    <#
    .SYNOPSIS
        Initializes the user location tracking system.
    .DESCRIPTION
        Bootstraps the centralized user logon CSV database by delegating to
        Initialize-CentralizedUserLogonCSV.  Returns $true on success,
        $false on failure.
    .OUTPUTS
        [bool]
    .EXAMPLE
        Initialize-UserLocationIndex
        Initializes the centralized database and returns $true if successful.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Log -Message "Initializing user location system" -Level "Info"

        # Bootstrap the centralized database
        $result = Initialize-CentralizedUserLogonCSV

        if ($result) {
            Write-Log -Message "Centralized user logon database initialized successfully" -Level "Info"
            return $true
        }
        else {
            Write-Log -Message "Failed to initialize centralized user logon database" -Level "Warning"
            return $false
        }
    }
    catch {
        Write-Log -Message "Error initializing user location index: $_" -Level "Error"
        return $false
    }
}

function Update-UserLocationIndex {
    <#
    .SYNOPSIS
        Verifies UserLogon.csv files across AD computers.
    .DESCRIPTION
        When called with -ComputerName, verifies the CSV on a single machine
        and optionally accepts a list of currently logged-in users.  Without
        -ComputerName, scans up to $maxComputers recently-active AD computers
        in parallel, showing a WinForms progress dialog.
    .PARAMETER Force
        Forces a full re-scan regardless of the last-update timestamp.
    .PARAMETER maxComputers
        Maximum number of AD computers to scan.  Defaults to 1000.
    .PARAMETER ComputerName
        Target a single computer instead of a full AD sweep.
    .PARAMETER LoggedInUsers
        ArrayList of users already known to be logged in on the target computer.
    .OUTPUTS
        [bool] when targeting a specific computer; otherwise $null (UI-driven).
    .EXAMPLE
        Update-UserLocationIndex -Force
        Scans all active AD computers for UserLogon.csv files.
    .EXAMPLE
        Update-UserLocationIndex -ComputerName "PC01" -LoggedInUsers $users
        Verifies the CSV on PC01 and records the supplied user list.
    #>
    param (
        [switch]$Force,
        [int]$maxComputers = 1000,
        [Parameter(ParameterSetName="SpecificComputer")]
        [string]$ComputerName,
        [Parameter(ParameterSetName="SpecificComputer")]
        [System.Collections.ArrayList]$LoggedInUsers
    )

    # Single-computer path
    if ($PSCmdlet.ParameterSetName -eq "SpecificComputer") {
        try {
            Write-Log -Message "Updating index for specific computer: $ComputerName" -Level "Verbose"

            # Verify the remote CSV is readable
            $csvPath = "\\$ComputerName\c$\ProgramData\IT\Logs\UserLogon.csv"
            if (Test-Path $csvPath) {
                try {
                    $csvData = Import-Csv -Path $csvPath -ErrorAction Stop
                    Write-Log -Message "Successfully verified CSV file on $ComputerName with $($csvData.Count) entries" -Level "Info"
                    return $true
                }
                catch {
                    Write-Log -Message "Error reading CSV file on $ComputerName`: $_" -Level "Warning"
                    return $false
                }
            }
            else {
                Write-Log -Message "CSV file not found on $ComputerName" -Level "Verbose"
            }

            # Fall back to live user data when CSV is absent
            if ($LoggedInUsers -and $LoggedInUsers.Count -gt 0) {
                Write-Log -Message "Found $($LoggedInUsers.Count) active users on $ComputerName" -Level "Verbose"
                return $true
            }
            else {
                Write-Log -Message "No logged in users found for $ComputerName, not updating index" -Level "Verbose"
                return $false
            }
        }
        catch {
            Write-Log -Message "Error updating index for specific computer $ComputerName`: $_" -Level "Error"
            return $false
        }
    }

    # Full-scan path -- build a progress dialog
    $progressForm = New-Object System.Windows.Forms.Form
    $progressForm.Text = "Verifying User Location CSV Files"
    $progressForm.Size = New-Object System.Drawing.Size(500, 200)
    $progressForm.StartPosition = "CenterScreen"
    $progressForm.FormBorderStyle = "FixedDialog"
    $progressForm.MaximizeBox = $false
    $progressForm.MinimizeBox = $false
    $progressForm.TopMost = $true

    $progressLabel = New-Object System.Windows.Forms.Label
    $progressLabel.Location = New-Object System.Drawing.Point(10, 20)
    $progressLabel.Size = New-Object System.Drawing.Size(470, 40)
    $progressLabel.Text = "Getting active computers from Active Directory..."
    $progressForm.Controls.Add($progressLabel)

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(10, 70)
    $progressBar.Size = New-Object System.Drawing.Size(470, 30)
    $progressBar.Style = "Continuous"
    $progressForm.Controls.Add($progressBar)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(10, 110)
    $statusLabel.Size = New-Object System.Drawing.Size(470, 40)
    $statusLabel.Text = "Starting CSV verification..."
    $progressForm.Controls.Add($statusLabel)

    $progressForm.Add_Shown({ $progressForm.Activate() })
    $progressForm.Show()
    [System.Windows.Forms.Application]::DoEvents()

    try {
            # Retrieve recently-active Windows computers from AD
            $progressLabel.Text = "Getting active computers from AD..."
            [System.Windows.Forms.Application]::DoEvents()

            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                $searcher.PageSize = 1000
                $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
                $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null

                $allComputers = $searcher.FindAll()

                $computers = $allComputers | ForEach-Object {
                    $lastLogon = 0
                    if ($_.Properties["lastLogonTimestamp"].Count -gt 0) {
                        $lastLogon = [DateTime]::FromFileTime([Int64]::Parse($_.Properties["lastLogonTimestamp"][0].ToString()))
                    }

                    $os = ""
                    if ($_.Properties["operatingSystem"].Count -gt 0) {
                        $os = $_.Properties["operatingSystem"][0].ToString()
                    }

                    # Only include Windows machines active in the last 30 days
                    if ($os -match "Windows" -and $lastLogon -gt (Get-Date).AddDays(-30)) {
                        [PSCustomObject]@{
                            Name      = $_.Properties["name"][0].ToString()
                            LastLogon = $lastLogon
                        }
                    }
                } | Sort-Object LastLogon -Descending | Select-Object -First $maxComputers
            }
            catch {
                Write-Log -Message "Error getting computers from AD: $_" -Level "Error"
                $computers = @()
            }

            $totalComputers = $computers.Count
            $progressBar.Maximum = $totalComputers
            $progressBar.Value = 0
            $statusLabel.Text = "Found $totalComputers computers to scan"
            [System.Windows.Forms.Application]::DoEvents()

            if ($totalComputers -gt 0) {
                # Determine batch size from settings or fall back to 10
                $batchSize = 10
                try {
                    if ($global:Settings -and $global:Settings.Performance -and $global:Settings.Performance.MaxConcurrentJobs) {
                        $batchSize = [Math]::Max(1, [int]$global:Settings.Performance.MaxConcurrentJobs)
                    }
                } catch {}
                $jobs = [System.Collections.ArrayList]::new()
                $processedCount = 0
            $successCount = 0
                $errorCount = 0

            # Mini-module injected into each background job
            $GetUserLogonCSVModule = @"
function Get-UserLogonCSV {
    param (
        [string]`$ComputerName
    )

    try {
        `$ComputerName = `$ComputerName.Split('.')[0].Trim()
        `$csvPath = "\\`$ComputerName\c$\ProgramData\IT\Logs\UserLogon.csv"

        if (-not (Test-Path -Path `$csvPath)) {
            Write-Output "CSV file not found on `$ComputerName"
        return `$false
    }

        try {
            `$csvData = Import-Csv -Path `$csvPath -ErrorAction Stop

            if (`$csvData -and `$csvData.Count -gt 0) {
                return `$true
                        }
                    }
                    catch {
            Write-Output "Error importing CSV from `$ComputerName`: `$_"
            return `$false
            }

        return `$false
        }
        catch {
        Write-Output "Error accessing `$ComputerName`: `$_"
        return `$false
    }
}
"@

            $TestComputerOnlineModule = @"
function Test-ComputerOnline {
    param (
        [string]`$ComputerName,
        [int]`$TimeoutMilliseconds = 500
    )

    try {
        `$ComputerName = `$ComputerName.Split('.')[0].Trim()
        return (Test-Connection -ComputerName `$ComputerName -Count 1 -Quiet -ErrorAction Stop)
    }
    catch {
        return `$false
    }
}
"@

                for ($i = 0; $i -lt $totalComputers; $i += $batchSize) {
                    # Harvest completed jobs to free resources
                    for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
                        if ($jobs[$j].State -eq "Completed") {
                            try {
                                $result = Receive-Job $jobs[$j] -ErrorAction Stop
                            if ($result -eq $true) {
                                $successCount++
                                }
                            }
                            catch {
                                Write-Log -Message "Error processing job result: $_" -Level "Warning"
                                $errorCount++
                            }
                            finally {
                                Remove-Job $jobs[$j] -Force -ErrorAction SilentlyContinue
                                $jobs.RemoveAt($j)

                                $processedCount++
                                $progressBar.Value = [Math]::Min($processedCount, $totalComputers)
                            $statusLabel.Text = "Processed $processedCount of $totalComputers computers. Found $successCount with CSV. Errors: $errorCount"
                                [System.Windows.Forms.Application]::DoEvents()
                            }
                        }
                    }

                    # Throttle concurrent jobs
                    while ($jobs.Count -ge $batchSize) {
                        Start-Sleep -Milliseconds 100

                        for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
                            if ($jobs[$j].State -eq "Completed") {
                                try {
                                    $result = Receive-Job $jobs[$j] -ErrorAction Stop
                                if ($result -eq $true) {
                                    $successCount++
                                    }
                                }
                                catch {
                                    Write-Log -Message "Error processing job result: $_" -Level "Warning"
                                    $errorCount++
                                }
                                finally {
                                    Remove-Job $jobs[$j] -Force -ErrorAction SilentlyContinue
                                    $jobs.RemoveAt($j)

                                    $processedCount++
                                    $progressBar.Value = [Math]::Min($processedCount, $totalComputers)
                                $statusLabel.Text = "Processed $processedCount of $totalComputers computers. Found $successCount with CSV. Errors: $errorCount"
                                    [System.Windows.Forms.Application]::DoEvents()
                                }
                            }
                        }
                    }

                    # Launch the next batch
                    $batch = $computers | Select-Object -Skip $i -First $batchSize
                    foreach ($computer in $batch) {
                        $computerName = $computer.Name
                        $statusLabel.Text = "Starting scan of $computerName ($($i + $jobs.Count + 1) of $totalComputers)"
                        [System.Windows.Forms.Application]::DoEvents()

                    # Background job: ping then check CSV
                        $job = Start-Job -ScriptBlock {
                            param($computerName, $testModule, $getUsersModule)

                            # Inject mini-modules into the job runspace
                            $ExecutionContext.InvokeCommand.InvokeScript($false, [ScriptBlock]::Create($testModule), $null, $null)
                            $ExecutionContext.InvokeCommand.InvokeScript($false, [ScriptBlock]::Create($getUsersModule), $null, $null)

                            if (Test-ComputerOnline -ComputerName $computerName) {
                            return Get-UserLogonCSV -ComputerName $computerName
                            }

                        return $false
                    } -ArgumentList $computerName, $TestComputerOnlineModule, $GetUserLogonCSVModule

                        [void]$jobs.Add($job)
                    }
                }

                # Drain remaining jobs
                while ($jobs.Count -gt 0) {
                    Start-Sleep -Milliseconds 100

                    for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
                        if ($jobs[$j].State -eq "Completed") {
                            try {
                                $result = Receive-Job $jobs[$j] -ErrorAction Stop
                            if ($result -eq $true) {
                                $successCount++
                                }
                            }
                            catch {
                                Write-Log -Message "Error processing job result: $_" -Level "Warning"
                                $errorCount++
                            }
                            finally {
                                Remove-Job $jobs[$j] -Force -ErrorAction SilentlyContinue
                                $jobs.RemoveAt($j)

                                $processedCount++
                                $progressBar.Value = [Math]::Min($processedCount, $totalComputers)
                            $statusLabel.Text = "Processed $processedCount of $totalComputers computers. Found $successCount with CSV. Errors: $errorCount"
                                [System.Windows.Forms.Application]::DoEvents()
                            }
                        }
                        elseif ($jobs[$j].State -eq "Failed") {
                            $errorCount++
                            Remove-Job $jobs[$j] -Force -ErrorAction SilentlyContinue
                            $jobs.RemoveAt($j)

                            $processedCount++
                            $progressBar.Value = [Math]::Min($processedCount, $totalComputers)
                        $statusLabel.Text = "Processed $processedCount of $totalComputers computers. Found $successCount with CSV. Errors: $errorCount"
                            [System.Windows.Forms.Application]::DoEvents()
                    }
                }
            }

            $statusLabel.Text = "Completed verification of $totalComputers computers. Found $successCount with CSV files."
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 2
        }
        else {
            $statusLabel.Text = "No computers found to scan."
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 2
        }

        # Persist the scan timestamp
        Set-UserLocationIndexLastUpdate -DateTime (Get-Date)
    }
    catch {
        Write-Log -Message "Error during CSV verification: $_" -Level "Error"
        $statusLabel.Text = "Error: $($_.Exception.Message)"
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Seconds 3
    }
    finally {
        $progressForm.Close()
        $progressForm.Dispose()
    }
}

function Get-UserLocationIndexAge {
    <#
    .SYNOPSIS
        Returns the age of the user location index as a TimeSpan.
    .DESCRIPTION
        Calculates the elapsed time since the last successful index update.
        If no update has been recorded, returns a 9999-day TimeSpan so that
        callers treat the index as stale.
    .OUTPUTS
        [TimeSpan]
    .EXAMPLE
        if ((Get-UserLocationIndexAge).TotalHours -gt 24) { Update-UserLocationIndex -Force }
        Re-scans when the index is older than one day.
    #>
    [CmdletBinding()]
    param()

    try {
        $lastUpdate = Get-UserLocationIndexLastUpdate
        if ($null -eq $lastUpdate) {
            # Treat missing timestamp as infinitely stale
            return [TimeSpan]::FromDays(9999)
        }

        return (Get-Date) - $lastUpdate
            }
            catch {
        Write-Log -Message "Error calculating user location index age: $_" -Level "Error"
        return [TimeSpan]::FromDays(9999)
    }
}

function Get-LoggedInUsers {
    <#
    .SYNOPSIS
        Retrieves logged-in users from a remote computer.
    .DESCRIPTION
        First attempts to read the UserLogon.csv on the remote machine.  If
        that fails or yields no results, falls back to a live quser query.
        Any live results are merged into the centralized database.
    .PARAMETER ComputerName
        NetBIOS or FQDN of the target computer.
    .PARAMETER TimeoutSeconds
        Seconds to wait for the quser query.  Defaults to 3.
    .OUTPUTS
        [PSCustomObject[]] with Username, ComputerName, SessionName, State,
        IdleTime, and LogonTime properties; or $null on failure.
    .EXAMPLE
        Get-LoggedInUsers -ComputerName "PC01"
        Returns user session objects for PC01.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [int]$TimeoutSeconds = 3
    )

    try {
        # Strip any domain suffix
        $ComputerName = $ComputerName.Split('.')[0].Trim()

        # Prefer the CSV data source
        $csvPath = "\\$ComputerName\c$\ProgramData\IT\Logs\UserLogon.csv"

        if (Test-Path $csvPath) {
            Write-Log -Message "Found UserLogon.csv on $ComputerName, reading data" -Level "Verbose"
            try {
                $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

                if ($csvData -and $csvData.Count -gt 0) {
                    $results = @()

                    foreach ($entry in $csvData) {
                        $username = $entry.Username
                        $timestamp = if ($entry.Timestamp) { $entry.Timestamp } else { (Get-Date).ToString() }
                        $action = if ($entry.Action) { $entry.Action } else { "Logon" }

                        # Only surface actual logon events
                        if (-not [string]::IsNullOrEmpty($username) -and $action -eq "Logon") {
                            $results += [PSCustomObject]@{
                                Username     = $username
                                ComputerName = $ComputerName
                                SessionName  = "CSV"
                                State        = "Active"
                                IdleTime     = "Unknown"
                                LogonTime    = $timestamp
                            }
                        }
                    }

                    if ($results.Count -gt 0) {
                        Write-Log -Message "Retrieved $($results.Count) user entries from CSV on $ComputerName" -Level "Verbose"
                        return $results
                    }
                }

                Write-Log -Message "No valid user entries found in CSV on $ComputerName" -Level "Verbose"
    }
    catch {
                Write-Log -Message "Error reading CSV file on $ComputerName`: $_" -Level "Warning"
                # Continue to the quser fallback below
            }
        }

        # Fall back to quser
        $results = @()

        $quserOutput = $null

        try {
            $quserOutput = quser /server:$ComputerName 2>$null
        }
        catch {
            Write-Output "Error querying users on $ComputerName`: $_"
            return $null
        }

        if ($quserOutput -and $quserOutput.Count -gt 1) {
            foreach ($line in $quserOutput | Select-Object -Skip 1) {
                try {
                    $username = $null
                    $sessionName = "Unknown"
                    $sessionState = "Unknown"
                    $idleTime = "Unknown"
                    $logonTime = "Unknown"

                    if ($line -match '^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                        # Standard format with session ID
                        $username = $matches[1]
                        $sessionName = $matches[2]
                        $sessionState = $matches[4]
                        $idleTime = $matches[5]
                        $logonTime = $matches[6] + " " + $matches[7]
                    }
                    elseif ($line -match '^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                        # Alternate format for disconnected sessions
                        $username = $matches[1]
                        $sessionName = $matches[2]
                        $sessionState = $matches[3]
                        $idleTime = $matches[4]
                        $logonTime = $matches[5] + " " + $matches[6]
                    }
                    else {
                        # Last-resort whitespace split
                        $parts = $line.Trim() -split '\s+'
                        if ($parts.Length -gt 0) {
                            $username = $parts[0]

                            if ($parts.Length -gt 1) { $sessionName = $parts[1] }
                            if ($parts.Length -gt 2) { $sessionState = $parts[2] }
                            if ($parts.Length -gt 3) { $idleTime = $parts[3] }
                            if ($parts.Length -gt 4) { $logonTime = ($parts[4..($parts.Length-1)] -join ' ') }
                        }
                    }

                    if (-not [string]::IsNullOrEmpty($username)) {
                        $results += [PSCustomObject]@{
                            Username     = $username
                            ComputerName = $ComputerName
                            SessionName  = $sessionName
                            State        = $sessionState
                            IdleTime     = $idleTime
                            LogonTime    = $logonTime
                        }
                    }
                }
                catch {
                    continue
                }
            }
        }

        # Merge live results into the centralized database
        if ($results -and $results.Count -gt 0) {
            try {
                $centralizedCsvPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"

                if (Test-Path $centralizedCsvPath) {
                    $existingData = Import-Csv -Path $centralizedCsvPath -ErrorAction Stop

                    $updatedEntries = @()

                    foreach ($entry in $existingData) {
                        # Drop stale entries for this computer; fresh ones follow
                        if ($entry.ComputerName -ne $ComputerName) {
                            $updatedEntries += $entry
                        }
                    }

                    foreach ($user in $results) {
                        $updatedEntries += [PSCustomObject]@{
                            Username     = $user.Username
                            ComputerName = $ComputerName
                            LastSeen     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Source       = "Live"
                            Action       = "Logon"
                            LogonTime    = $user.LogonTime
                            SessionID    = $user.SessionName
                            IPAddress    = ""
                            UserFullName = ""
                            DomainName   = ""
                        }
                    }

                    $updatedEntries | Export-Csv -Path $centralizedCsvPath -NoTypeInformation -Force
                    Write-Log -Message "Updated centralized database with live user data from $ComputerName" -Level "Verbose"
                }
                else {
                    # Database does not exist yet -- create it
                    Initialize-CentralizedUserLogonCSV

                    $newEntries = @()
                    foreach ($user in $results) {
                        $newEntries += [PSCustomObject]@{
                            Username     = $user.Username
                            ComputerName = $ComputerName
                            LastSeen     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Source       = "Live"
                            Action       = "Logon"
                            LogonTime    = $user.LogonTime
                            SessionID    = $user.SessionName
                            IPAddress    = ""
                            UserFullName = ""
                            DomainName   = ""
                        }
                    }

                    $newEntries | Export-Csv -Path $centralizedCsvPath -NoTypeInformation -Force
                    Write-Log -Message "Created new centralized database with live user data from $ComputerName" -Level "Verbose"
                }
            }
            catch {
                Write-Log -Message "Error updating centralized database with live user data: $_" -Level "Warning"
            }
        }

        return $results
    }
    catch {
        Write-Output "Exception in Get-LoggedInUsers for $ComputerName`: $_"
        return $null
    }
}

function Get-UserLocationIndexLastUpdate {
    <#
    .SYNOPSIS
        Reads the last-update timestamp for the user location index.
    .DESCRIPTION
        Retrieves the persisted DateTime value from the registry key
        HKCU:\Software\IT\ADapp\UserLocationIndexLastUpdate.  Returns
        $null if the key does not exist or the value cannot be parsed.
    .OUTPUTS
        [DateTime] or $null
    .EXAMPLE
        $lastUpdate = Get-UserLocationIndexLastUpdate
        Reads the timestamp of the most recent index refresh.
    #>
    [CmdletBinding()]
    param()

    try {
        $regPath = "HKCU:\Software\IT\ADapp"

        if (Test-Path -Path $regPath) {
            $lastUpdate = Get-ItemProperty -Path $regPath -Name "UserLocationIndexLastUpdate" -ErrorAction SilentlyContinue

            if ($lastUpdate -and $lastUpdate.UserLocationIndexLastUpdate) {
                try {
                    return [DateTime]::Parse($lastUpdate.UserLocationIndexLastUpdate)
                }
                catch {
                    Write-Log -Message "Error parsing date from registry: $_" -Level "Warning"
                    return $null
                }
            }
        }

        return $null
    }
    catch {
        Write-Log -Message "Error getting user location index timestamp from registry: $_" -Level "Warning"
        return $null
    }
}

function Set-UserLocationIndexLastUpdate {
    <#
    .SYNOPSIS
        Persists the last-update timestamp for the user location index.
    .DESCRIPTION
        Writes an ISO-8601 round-trip formatted DateTime string to the
        registry key HKCU:\Software\IT\ADapp\UserLocationIndexLastUpdate.
        Creates the key path if it does not already exist.
    .PARAMETER DateTime
        The DateTime value to persist.
    .OUTPUTS
        [bool]
    .EXAMPLE
        Set-UserLocationIndexLastUpdate -DateTime (Get-Date)
        Records the current time as the latest index update.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$DateTime
    )

    try {
        $regPath = "HKCU:\Software\IT\ADapp"

        if (-not (Test-Path -Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        New-ItemProperty -Path $regPath -Name "UserLocationIndexLastUpdate" -Value $DateTime.ToString("o") -PropertyType String -Force | Out-Null

        return $true
    }
    catch {
        Write-Log -Message "Error setting user location index timestamp in registry: $_" -Level "Error"
        return $false
    }
}

function Get-UserLocationForUsername {
    <#
    .SYNOPSIS
        Looks up the last-known location for a username in the legacy index.
    .DESCRIPTION
        Searches the in-memory user location index (from Get-UserLocationIndex)
        for an exact or partial username match and returns the associated
        location string.
    .PARAMETER Username
        The sAMAccountName to search for.
    .OUTPUTS
        [string] -- location value or empty string if not found.
    .EXAMPLE
        Get-UserLocationForUsername -Username "jsmith"
        Returns the last-known computer location for jsmith.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Username)) {
            return ""
        }

        if (-not (Test-Path $global:AppConfig.UserLocationIndexFile)) {
            Write-Log -Message "User location index file not found" -Level "Warning"
            return ""
        }

        $userLocations = Get-UserLocationIndex

        if ($null -eq $userLocations -or $userLocations.Count -eq 0) {
            Write-Log -Message "User location index is empty or could not be loaded" -Level "Warning"
            return ""
        }

        # Exact match first
        foreach ($user in $userLocations.Keys) {
            if ($user -eq $Username) {
                return $userLocations[$user]
            }
        }

        # Wildcard fallback
        foreach ($user in $userLocations.Keys) {
            if ($user -like "*$Username*") {
                return $userLocations[$user]
            }
        }

        return ""
    }
    catch {
        Write-Log -Message "Error getting user location for $Username`: $_" -Level "Error"
        return ""
    }
}

function Get-UserLocationFromCentralizedDB {
    <#
    .SYNOPSIS
        Queries the centralized user logon database for a given username.
    .DESCRIPTION
        Maintains a 5-minute in-memory cache of the CentralizedUserLogon.csv
        and returns all matching entries for the specified username, sorted
        by LastSeen descending.  Matching is case-insensitive and supports
        domain-prefixed or bare usernames.
    .PARAMETER Username
        The sAMAccountName (with or without domain prefix) to search for.
    .OUTPUTS
        [PSCustomObject[]] -- matching database rows, or empty array.
    .EXAMPLE
        Get-UserLocationFromCentralizedDB -Username "jsmith"
        Returns all centralized logon entries for jsmith.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Username)) {
            return @()
        }

        # Refresh cache when stale (> 5 min) or missing
        if (-not $script:CentralizedDBCache -or
            -not $script:CentralizedDBCacheTime -or
            ((Get-Date) - $script:CentralizedDBCacheTime).TotalMinutes -gt 5) {

            $centralizedCsvPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"
            if (Test-Path $centralizedCsvPath) {
                try {
                    Write-Log -Message "Loading centralized DB into cache" -Level "Verbose"
                    $script:CentralizedDBCache = Import-Csv -Path $centralizedCsvPath -ErrorAction Stop
                    $script:CentralizedDBCacheTime = Get-Date
                }
                catch {
                    Write-Log -Message "Error reading centralized CSV for cache: $_" -Level "Warning"
                    $script:CentralizedDBCache = @()
                    $script:CentralizedDBCacheTime = Get-Date
                }
            }
            else {
                $script:CentralizedDBCache = @()
                $script:CentralizedDBCacheTime = Get-Date
            }
        }

        if ($script:CentralizedDBCache -and $script:CentralizedDBCache.Count -gt 0) {
            # Case-insensitive match supporting domain-prefixed names
            $userEntries = $script:CentralizedDBCache | Where-Object {
                $_.Username -eq $Username -or
                $_.Username -like "*\$Username" -or
                $_.Username -like "$Username*"
            } | Sort-Object -Property LastSeen -Descending

            if ($userEntries -and $userEntries.Count -gt 0) {
                return $userEntries
            }
        }

        return @()
    }
    catch {
        Write-Log -Message "Error getting user location for $Username`: $_" -Level "Error"
        return @()
    }
}

function Test-ComputerOnline {
    <#
    .SYNOPSIS
        Tests whether a computer responds to ICMP ping with optional caching.
    .DESCRIPTION
        Pings the target computer up to $Retries times.  Results are cached
        for 30 seconds to avoid redundant network traffic during batch scans.
        Use -IgnoreCache to bypass the cache.
    .PARAMETER ComputerName
        NetBIOS or FQDN of the target computer.
    .PARAMETER TimeoutMilliseconds
        Ping timeout in milliseconds.  Defaults to 200.
    .PARAMETER Retries
        Number of ping attempts before declaring the host offline.  Defaults to 1.
    .PARAMETER IgnoreCache
        When specified, skips the 30-second result cache.
    .OUTPUTS
        [bool]
    .EXAMPLE
        Test-ComputerOnline -ComputerName "PC01"
        Returns $true if PC01 responds to ping.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [int]$TimeoutMilliseconds = 200,
        [int]$Retries = 1,
        [switch]$IgnoreCache
    )

    try {
        $ComputerName = $ComputerName.Split('.')[0].Trim()

        # Return cached result when fresh enough
        if (-not $IgnoreCache -and $script:OnlineComputerCache) {
            $cacheExpiration = 30

            if ($script:OnlineComputerCache.ContainsKey($ComputerName)) {
                $cachedResult = $script:OnlineComputerCache[$ComputerName]

                if (((Get-Date) - $cachedResult.Timestamp).TotalSeconds -lt $cacheExpiration) {
                    return $cachedResult.IsOnline
                }
            }
        }

        if (-not $script:OnlineComputerCache) {
            $script:OnlineComputerCache = @{}
        }

        $isOnline = $false
        for ($i = 0; $i -lt $Retries; $i++) {
            try {
                $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
                if ($pingResult) {
                    $isOnline = $true
                    break
                }

                if ($i -lt $Retries - 1) {
                    Start-Sleep -Milliseconds 50
                }
            }
            catch {
                continue
            }
        }

        $script:OnlineComputerCache[$ComputerName] = @{
            IsOnline  = $isOnline
            Timestamp = Get-Date
        }

        return $isOnline
    }
    catch {
        Write-Output "Error testing connection to $ComputerName`: $_"
        return $false
    }
}

function Show-UserLocationIndex {
    <#
    .SYNOPSIS
        Displays a WinForms dialog showing all user logon locations from CSV files.
    .DESCRIPTION
        Opens a searchable ListView window that scans online AD computers for
        UserLogon.csv data.  Includes a refresh button and live text filtering.
    .OUTPUTS
        None (UI dialog).
    .EXAMPLE
        Show-UserLocationIndex
        Opens the user location viewer window.
    #>
    [CmdletBinding()]
    param()

    try {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "User Location Index from CSV Files"
        $form.Size = New-Object System.Drawing.Size(800, 500)
        $form.StartPosition = "CenterScreen"
        $form.MinimizeBox = $false
        $form.MaximizeBox = $true
        $form.WindowState = "Normal"
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable

        $listView = New-Object System.Windows.Forms.ListView
        $listView.View = [System.Windows.Forms.View]::Details
        $listView.FullRowSelect = $true
        $listView.GridLines = $true
        $listView.Dock = [System.Windows.Forms.DockStyle]::Fill
        $listView.Sorting = [System.Windows.Forms.SortOrder]::Ascending

        $listView.Columns.Add("Username", 150) | Out-Null
        $listView.Columns.Add("Computer", 150) | Out-Null
        $listView.Columns.Add("Last Seen", 150) | Out-Null
        $listView.Columns.Add("Source", 100) | Out-Null

        $countPanel = New-Object System.Windows.Forms.Panel
        $countPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
        $countPanel.Height = 30

        $countLabel = New-Object System.Windows.Forms.Label
        $countLabel.Location = New-Object System.Drawing.Point(10, 5)
        $countLabel.Size = New-Object System.Drawing.Size(570, 20)
        $countLabel.Text = "Loading user location data..."
        $countPanel.Controls.Add($countLabel)

        $searchPanel = New-Object System.Windows.Forms.Panel
        $searchPanel.Dock = [System.Windows.Forms.DockStyle]::Top
        $searchPanel.Height = 40

        $searchLabel = New-Object System.Windows.Forms.Label
        $searchLabel.Location = New-Object System.Drawing.Point(10, 14)
        $searchLabel.Size = New-Object System.Drawing.Size(60, 20)
        $searchLabel.Text = "Search:"
        $searchPanel.Controls.Add($searchLabel)

        $searchBox = New-Object System.Windows.Forms.TextBox
        $searchBox.Location = New-Object System.Drawing.Point(80, 10)
        $searchBox.Size = New-Object System.Drawing.Size(300, 20)
        $searchPanel.Controls.Add($searchBox)

        $buttonPanel = New-Object System.Windows.Forms.Panel
        $buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
        $buttonPanel.Height = 40

        $refreshButton = New-Object System.Windows.Forms.Button
        $refreshButton.Location = New-Object System.Drawing.Point(10, 8)
        $refreshButton.Size = New-Object System.Drawing.Size(100, 25)
        $refreshButton.Text = "Refresh"

        # Nested helper: scan online computers and return CSV-based user entries
        function Get-AllUserLocationsFromCSV {
            <#
            .SYNOPSIS
                Collects user logon entries from CSV files on online AD computers.
            .DESCRIPTION
                Queries AD for recently-active Windows computers, pings them, and
                reads their UserLogon.csv files.  Optionally filters by a text string.
            .PARAMETER Filter
                Optional text filter applied to Username and ComputerName.
            .OUTPUTS
                [PSCustomObject[]] with Username, ComputerName, LastSeen, Source.
            .EXAMPLE
                Get-AllUserLocationsFromCSV -Filter "jsmith"
            #>
            param (
                [string]$Filter = ""
            )

            $results = @()

            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                $searcher.PageSize = 1000
                $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
                $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null

                $allComputers = $searcher.FindAll()

                $computers = $allComputers | ForEach-Object {
                    $lastLogon = 0
                    if ($_.Properties["lastLogonTimestamp"].Count -gt 0) {
                        $lastLogon = [DateTime]::FromFileTime([Int64]::Parse($_.Properties["lastLogonTimestamp"][0].ToString()))
                    }

                    $os = ""
                    if ($_.Properties["operatingSystem"].Count -gt 0) {
                        $os = $_.Properties["operatingSystem"][0].ToString()
                    }

                    if ($os -match "Windows" -and $lastLogon -gt (Get-Date).AddDays(-30)) {
                        [PSCustomObject]@{
                            Name      = $_.Properties["name"][0].ToString()
                            LastLogon = $lastLogon
                        }
                    }
                } | Sort-Object LastLogon -Descending | Select-Object -First 500
            }
            catch {
                Write-Log -Message "Error getting computers from AD: $_" -Level "Error"
                $computers = @()
            }

            $onlineComputers = @()
            foreach ($computer in $computers) {
                if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    $onlineComputers += $computer
                }
            }

            foreach ($computer in $onlineComputers) {
                $computerName = $computer.Name

                $csvPath = "\\$computerName\c$\ProgramData\IT\Logs\UserLogon.csv"
                if (Test-Path $csvPath) {
                    try {
                        $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

                        foreach ($entry in $csvData) {
                            if ([string]::IsNullOrEmpty($Filter) -or
                                $entry.Username -like "*$Filter*" -or
                                $computerName -like "*$Filter*") {

                                if ([DateTime]::TryParse($entry.LogonTime, [ref]$null)) {
                                    $results += [PSCustomObject]@{
                                        Username     = $entry.Username
                                        ComputerName = $computerName
                                        LastSeen     = [DateTime]::Parse($entry.LogonTime)
                                        Source       = "CSV"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log -Message "Error reading CSV from $computerName`: $_" -Level "Warning"
                    }
                }
            }

            return $results | Sort-Object Username
        }

        # Nested helper: populate the ListView from CSV scan results
        function Update-ListView {
            <#
            .SYNOPSIS
                Refreshes the ListView control with user location data.
            .DESCRIPTION
                Calls Get-AllUserLocationsFromCSV, clears the ListView, and
                re-populates it with the returned entries.
            .PARAMETER Filter
                Optional text filter passed through to Get-AllUserLocationsFromCSV.
            .OUTPUTS
                None (updates UI controls).
            .EXAMPLE
                Update-ListView -Filter "PC01"
            #>
            param (
                [string]$Filter = ""
            )

            $listView.Items.Clear()
            $countLabel.Text = "Loading user location data..."
            [System.Windows.Forms.Application]::DoEvents()

            $data = Get-AllUserLocationsFromCSV -Filter $Filter

            foreach ($entry in $data) {
                $item = New-Object System.Windows.Forms.ListViewItem($entry.Username)
                $item.SubItems.Add($entry.ComputerName)
                $item.SubItems.Add($entry.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"))
                $item.SubItems.Add($entry.Source)
                    $listView.Items.Add($item) | Out-Null
                }

            $countLabel.Text = "Total Entries: $($data.Count) | Last Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        }

        $refreshButton.Add_Click({
            Update-ListView -Filter $searchBox.Text.Trim()
        })
        $buttonPanel.Controls.Add($refreshButton)

        $searchBox.Add_TextChanged({
            Update-ListView -Filter $searchBox.Text.Trim()
        })

        $form.Controls.Add($listView)
        $form.Controls.Add($countPanel)
        $form.Controls.Add($searchPanel)
        $form.Controls.Add($buttonPanel)

        $form.Add_Shown({
            Update-ListView
        })

        $form.ShowDialog() | Out-Null
    }
    catch {
        Write-Log -Message "Error displaying user location index: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred while trying to display the user location index:`n$_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Get-UserLocation {
    <#
    .SYNOPSIS
        Locates a user across all AD computers using CSV data and live queries.
    .DESCRIPTION
        Searches recently-active AD computers for the given username by reading
        each machine's UserLogon.csv.  Falls back to live quser lookup when no
        CSV data is found.  Optionally refreshes the index cache first.
    .PARAMETER Username
        The sAMAccountName to search for.
    .PARAMETER RefreshCache
        Forces an index refresh before searching.
    .PARAMETER IncludeUserDetails
        Reserved for future use.
    .OUTPUTS
        [PSCustomObject[]] sorted by LastSeen descending.
    .EXAMPLE
        Get-UserLocation -Username "jsmith"
        Returns the most recent logon locations for jsmith.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [switch]$RefreshCache,
        [switch]$IncludeUserDetails
    )

    if ([string]::IsNullOrEmpty($Username)) {
        return $null
    }

    # Normalise to bare sAMAccountName
    $Username = $Username.Split('\')[-1].Split('@')[0].Trim()

    # Refresh when stale (> 1 day) or explicitly requested
    if ($RefreshCache -or (Get-UserLocationIndexAge).TotalDays -gt 1) {
        Write-Log -Message "Refreshing user location cache" -Level "Verbose"
        Update-UserLocationIndex -Force
    }

    $results = @()

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null

        $allComputers = $searcher.FindAll()

        $computers = $allComputers | ForEach-Object {
            $lastLogon = 0
            if ($_.Properties["lastLogonTimestamp"].Count -gt 0) {
                $lastLogon = [DateTime]::FromFileTime([Int64]::Parse($_.Properties["lastLogonTimestamp"][0].ToString()))
            }

            $os = ""
            if ($_.Properties["operatingSystem"].Count -gt 0) {
                $os = $_.Properties["operatingSystem"][0].ToString()
            }

            if ($os -match "Windows" -and $lastLogon -gt (Get-Date).AddDays(-30)) {
                [PSCustomObject]@{
                    Name      = $_.Properties["name"][0].ToString()
                    LastLogon = $lastLogon
                }
            }
        } | Sort-Object LastLogon -Descending | Select-Object -First 1000
                }
                catch {
        Write-Log -Message "Error getting computers from AD: $_" -Level "Error"
        $computers = @()
    }

    foreach ($computer in $computers) {
        $computerName = $computer.Name

        if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            continue
        }

        $csvPath = "\\$computerName\c$\ProgramData\IT\Logs\UserLogon.csv"
        if (Test-Path $csvPath) {
            try {
                $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

                $userEntries = $csvData | Where-Object { $_.Username -eq $Username }

                if ($userEntries -and $userEntries.Count -gt 0) {
                    $latestEntry = $userEntries |
                                   Where-Object { [DateTime]::TryParse($_.LogonTime, [ref]$null) } |
                                   Sort-Object { [DateTime]::Parse($_.LogonTime) } -Descending |
                                   Select-Object -First 1

                    if ($latestEntry) {
                        $result = [PSCustomObject]@{
                            Username     = $Username
                            ComputerName = $computerName
                            LastSeen     = [DateTime]::Parse($latestEntry.LogonTime)
                            Source       = "CSV"
                        }

                        if ($latestEntry.PSObject.Properties.Name -contains "UserFullName") {
                            $result | Add-Member -MemberType NoteProperty -Name "UserFullName" -Value $latestEntry.UserFullName
                        }

                        if ($latestEntry.PSObject.Properties.Name -contains "SessionID") {
                            $result | Add-Member -MemberType NoteProperty -Name "SessionID" -Value $latestEntry.SessionID
                        }

                        $results += $result
                    }
                    }
                }
                catch {
                Write-Log -Message "Error reading CSV from $computerName`: $_" -Level "Warning"
            }
        }

        # Live lookup fallback when no CSV data has been gathered yet
        if ($results.Count -eq 0) {
            try {
                $users = Get-LoggedInUsers -ComputerName $computerName

                $matchingUsers = $users | Where-Object { $_.Username -eq $Username }
                if ($matchingUsers -and $matchingUsers.Count -gt 0) {
                    foreach ($user in $matchingUsers) {
                        $results += [PSCustomObject]@{
                            Username     = $Username
                            ComputerName = $computerName
                            LastSeen     = [DateTime]::Now
                            Source       = "Live"
                            SessionID    = $user.SessionID
                        }
                    }
                }
    }
    catch {
                Write-Log -Message "Error getting logged in users from $computerName`: $_" -Level "Warning"
            }
        }
    }

    return $results | Sort-Object LastSeen -Descending
}

function Show-ComputerUserLogonCSV {
    <#
    .SYNOPSIS
        Displays the UserLogon.csv contents for a specific computer.
    .DESCRIPTION
        Opens a WinForms dialog showing the raw CSV data from a remote
        computer's UserLogon.csv.  If no computer name is supplied, a
        selector dialog is presented.  Supports search, refresh, and
        CSV export.
    .PARAMETER ComputerName
        Optional computer name.  When omitted a picker dialog is shown.
    .OUTPUTS
        None (UI dialog).
    .EXAMPLE
        Show-ComputerUserLogonCSV -ComputerName "PC01"
        Opens the CSV viewer for PC01.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ComputerName
    )

    try {
        # Prompt for a computer name when none is supplied
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Select Computer"
            $form.Size = New-Object System.Drawing.Size(400, 200)
            $form.StartPosition = "CenterScreen"
            $form.FormBorderStyle = "FixedDialog"
            $form.MaximizeBox = $false
            $form.MinimizeBox = $false

            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(10, 20)
            $label.Size = New-Object System.Drawing.Size(380, 20)
            $label.Text = "Enter computer name:"
            $form.Controls.Add($label)

            $textBox = New-Object System.Windows.Forms.TextBox
            $textBox.Location = New-Object System.Drawing.Point(10, 50)
            $textBox.Size = New-Object System.Drawing.Size(360, 20)
            $form.Controls.Add($textBox)

            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(210, 120)
            $okButton.Size = New-Object System.Drawing.Size(75, 23)
            $okButton.Text = "OK"
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Controls.Add($okButton)
            $form.AcceptButton = $okButton

            $cancelButton = New-Object System.Windows.Forms.Button
            $cancelButton.Location = New-Object System.Drawing.Point(295, 120)
            $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
            $cancelButton.Text = "Cancel"
            $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $form.Controls.Add($cancelButton)
            $form.CancelButton = $cancelButton

            $adComputersLabel = New-Object System.Windows.Forms.Label
            $adComputersLabel.Location = New-Object System.Drawing.Point(10, 80)
            $adComputersLabel.Size = New-Object System.Drawing.Size(380, 20)
            $adComputersLabel.Text = "Or select from recent computers:"
            $form.Controls.Add($adComputersLabel)

            $adComputersComboBox = New-Object System.Windows.Forms.ComboBox
            $adComputersComboBox.Location = New-Object System.Drawing.Point(10, 100)
            $adComputersComboBox.Size = New-Object System.Drawing.Size(180, 20)
            $adComputersComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
            $form.Controls.Add($adComputersComboBox)

            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                $searcher.PageSize = 1000
                $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null

                $allComputers = $searcher.FindAll()

                $computers = $allComputers | ForEach-Object {
                    $lastLogon = 0
                    if ($_.Properties["lastLogonTimestamp"].Count -gt 0) {
                        $lastLogon = [DateTime]::FromFileTime([Int64]::Parse($_.Properties["lastLogonTimestamp"][0].ToString()))
                    }

                    if ($lastLogon -gt (Get-Date).AddDays(-30)) {
                        [PSCustomObject]@{
                            Name      = $_.Properties["name"][0].ToString()
                            LastLogon = $lastLogon
                        }
                    }
                } | Sort-Object LastLogon -Descending | Select-Object -First 20 | Select-Object -ExpandProperty Name

                foreach ($computer in $computers) {
                    $adComputersComboBox.Items.Add($computer) | Out-Null
                }

                if ($adComputersComboBox.Items.Count -gt 0) {
                    $adComputersComboBox.SelectedIndex = 0
        }
    }
    catch {
                Write-Log -Message "Error getting AD computers: $_" -Level "Warning"
            }

            $adComputersComboBox.Add_SelectedIndexChanged({
                $textBox.Text = $adComputersComboBox.SelectedItem
            })

            $result = $form.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $ComputerName = $textBox.Text.Trim()
            }
            else {
                return
            }
        }

        if (-not (Test-ComputerOnline -ComputerName $ComputerName)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Computer '$ComputerName' is not reachable.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        $csvPath = "\\$ComputerName\c$\ProgramData\IT\Logs\UserLogon.csv"
        if (-not (Test-Path $csvPath)) {
            [System.Windows.Forms.MessageBox]::Show(
                "UserLogon.csv file not found on computer '$ComputerName'.",
                "File Not Found",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        try {
            $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

            if ($null -eq $csvData -or $csvData.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "UserLogon.csv file on computer '$ComputerName' is empty.",
                    "Empty File",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                return
            }

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "User Logon Data for $ComputerName"
            $form.Size = New-Object System.Drawing.Size(900, 600)
            $form.StartPosition = "CenterScreen"
            $form.MinimizeBox = $true
            $form.MaximizeBox = $true

            $listView = New-Object System.Windows.Forms.ListView
            $listView.View = [System.Windows.Forms.View]::Details
            $listView.FullRowSelect = $true
            $listView.GridLines = $true
            $listView.Location = New-Object System.Drawing.Point(10, 10)
            $listView.Size = New-Object System.Drawing.Size(865, 480)
            $listView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

            $headers = $csvData[0].PSObject.Properties.Name
            foreach ($header in $headers) {
                $width = switch ($header) {
                    "Username"     { 120 }
                    "LogonTime"    { 150 }
                    "ComputerName" { 120 }
                    "IPAddress"    { 120 }
                    "Action"       { 80 }
                    "Domain"       { 100 }
                    "UserFullName" { 200 }
                    default        { 120 }
                }

                $listView.Columns.Add($header, $width) | Out-Null
            }

            foreach ($row in $csvData) {
                $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                for ($i = 1; $i -lt $headers.Count; $i++) {
                    $item.SubItems.Add($row.($headers[$i])) | Out-Null
                }

                $listView.Items.Add($item) | Out-Null
            }

            $statusLabel = New-Object System.Windows.Forms.Label
            $statusLabel.Location = New-Object System.Drawing.Point(10, 500)
            $statusLabel.Size = New-Object System.Drawing.Size(865, 20)
            $statusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
            $statusLabel.Text = "Total entries: $($csvData.Count) | CSV Path: $csvPath"

            $searchPanel = New-Object System.Windows.Forms.Panel
            $searchPanel.Location = New-Object System.Drawing.Point(10, 520)
            $searchPanel.Size = New-Object System.Drawing.Size(865, 35)
            $searchPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

            $searchLabel = New-Object System.Windows.Forms.Label
            $searchLabel.Location = New-Object System.Drawing.Point(0, 8)
            $searchLabel.Size = New-Object System.Drawing.Size(60, 20)
            $searchLabel.Text = "Search:"
            $searchPanel.Controls.Add($searchLabel)

            $searchBox = New-Object System.Windows.Forms.TextBox
            $searchBox.Location = New-Object System.Drawing.Point(65, 5)
            $searchBox.Size = New-Object System.Drawing.Size(200, 20)
            $searchPanel.Controls.Add($searchBox)

            $searchButton = New-Object System.Windows.Forms.Button
            $searchButton.Location = New-Object System.Drawing.Point(275, 4)
            $searchButton.Size = New-Object System.Drawing.Size(75, 23)
            $searchButton.Text = "Search"
            $searchPanel.Controls.Add($searchButton)

            $refreshButton = New-Object System.Windows.Forms.Button
            $refreshButton.Location = New-Object System.Drawing.Point(360, 4)
            $refreshButton.Size = New-Object System.Drawing.Size(75, 23)
            $refreshButton.Text = "Refresh"
            $searchPanel.Controls.Add($refreshButton)

            $exportButton = New-Object System.Windows.Forms.Button
            $exportButton.Location = New-Object System.Drawing.Point(445, 4)
            $exportButton.Size = New-Object System.Drawing.Size(100, 23)
            $exportButton.Text = "Export to CSV"
            $searchPanel.Controls.Add($exportButton)

            $searchFunction = {
                $searchText = $searchBox.Text.Trim()
                $listView.Items.Clear()

                if ([string]::IsNullOrEmpty($searchText)) {
                    foreach ($row in $csvData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    # Auto-select single match for quick keyboard workflows
                    if ($listView.Items.Count -eq 1) {
                        try {
                            $listView.Items[0].Selected = $true
                            $listView.Items[0].Focused = $true
                            $listView.EnsureVisible(0)
                            $listView.Select()
                            $listView.Focus()
                        } catch {}
                    }

                    $statusLabel.Text = "Total entries: $($csvData.Count) | CSV Path: $csvPath"
                }
                else {
                    $filteredData = $csvData | Where-Object {
                        $match = $false
                        foreach ($prop in $_.PSObject.Properties) {
                            if ($prop.Value -like "*$searchText*") {
                                $match = $true
                        break
                    }
                        }
                        $match
                    }

                    foreach ($row in $filteredData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    # Auto-select single match for quick keyboard workflows
                    if ($listView.Items.Count -eq 1) {
                        try {
                            $listView.Items[0].Selected = $true
                            $listView.Items[0].Focused = $true
                            $listView.EnsureVisible(0)
                            $listView.Select()
                            $listView.Focus()
                        } catch {}
                    }

                    $statusLabel.Text = "Filtered entries: $($listView.Items.Count) of $($csvData.Count) | CSV Path: $csvPath"
                }
            }

            $searchButton.Add_Click($searchFunction)
            $searchBox.Add_KeyDown({
                if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
                    $searchFunction.Invoke()
                }
            })

            $refreshButton.Add_Click({
                try {
                    $script:csvData = Import-Csv -Path $csvPath -ErrorAction Stop
                    $listView.Items.Clear()

                    foreach ($row in $script:csvData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    $statusLabel.Text = "Total entries: $($script:csvData.Count) | CSV Path: $csvPath | Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Error refreshing data: $_",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            })

            $exportButton.Add_Click({
                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export CSV Data"
                $saveFileDialog.FileName = "UserLogon_$ComputerName.csv"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    try {
                        $csvData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
                        [System.Windows.Forms.MessageBox]::Show(
                            "Data exported successfully to $($saveFileDialog.FileName).",
                            "Export Successful",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Information
                        )
                    }
                    catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Error exporting data: $_",
                            "Export Error",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                    }
                }
            })

            $form.Controls.Add($listView)
            $form.Controls.Add($statusLabel)
            $form.Controls.Add($searchPanel)

            $form.ShowDialog() | Out-Null
    }
    catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error reading CSV file: $_",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
    catch {
        Write-Log -Message "Error in Show-ComputerUserLogonCSV: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Initialize-CentralizedUserLogonCSV {
    <#
    .SYNOPSIS
        Creates or re-initialises the centralized user logon CSV database.
    .DESCRIPTION
        Ensures that CentralizedUserLogon.csv exists under $global:AppConfig.DataPath
        with the correct column headers.  Optionally backs up and overwrites an
        existing file when -Force is specified.
    .PARAMETER Force
        When specified, backs up and recreates the database even if it already exists.
    .OUTPUTS
        [bool]
    .EXAMPLE
        Initialize-CentralizedUserLogonCSV -Force
        Backs up the current database and creates a fresh empty file.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    try {
        $csvPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"
        $csvBackupPath = Join-Path -Path $global:AppConfig.IndexBackupPath -ChildPath "CentralizedUserLogon_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

        if (Test-Path $csvPath) {
            $fileInfo = Get-Item $csvPath
            # Back up when forced or when the file is stale (> 1 day)
            if ($Force -or $fileInfo.LastWriteTime -lt (Get-Date).AddDays(-1)) {
                try {
                    Copy-Item -Path $csvPath -Destination $csvBackupPath -Force
                    Write-Log -Message "Backed up centralized user logon CSV to $csvBackupPath" -Level "Info"
                }
                catch {
                    Write-Log -Message "Failed to back up centralized user logon CSV: $_" -Level "Warning"
                }
            }

            if (-not $Force) {
                return $true
            }
        }

        if ($Force -or -not (Test-Path $csvPath)) {
            $headers = @(
                "Username",
                "ComputerName",
                "LastSeen",
                "Source",
                "Action",
                "IPAddress",
                "UserFullName",
                "LogonTime",
                "SessionID",
                "DomainName"
            )

            $headers -join "," | Out-File -FilePath $csvPath -Encoding utf8 -Force
            Write-Log -Message "Created new centralized user logon CSV file" -Level "Info"
        }

        return $true
    }
    catch {
        Write-Log -Message "Error initializing centralized user logon CSV: $_" -Level "Error"
        return $false
    }
}

function Update-CentralizedUserLogonCSV {
    <#
    .SYNOPSIS
        Collects UserLogon.csv data from AD computers into the centralized database.
    .DESCRIPTION
        Scans recently-active AD computers in parallel background jobs, reads each
        machine's UserLogon.csv (or falls back to quser), and merges the results
        into the centralized CentralizedUserLogon.csv.  A WinForms progress dialog
        is displayed during the operation.
    .PARAMETER Force
        Re-initialises the centralized CSV before collecting data.
    .PARAMETER maxComputers
        Maximum number of AD computers to scan.  Defaults to 1000.
    .PARAMETER ComputerName
        Target a single computer instead of a full AD sweep.
    .PARAMETER MaxParallelJobs
        Maximum number of concurrent background jobs.  Defaults to 20 or
        the value from $global:Settings.Performance.MaxConcurrentJobs.
    .OUTPUTS
        [bool]
    .EXAMPLE
        Update-CentralizedUserLogonCSV -Force -maxComputers 500
        Re-initialises the database and scans up to 500 computers.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [int]$maxComputers = 1000,
        [Parameter(ParameterSetName="SpecificComputer")]
        [string]$ComputerName,
        [int]$MaxParallelJobs = 20
    )

    # Honour application-level concurrency setting when not explicitly overridden
    try {
        if (-not $PSBoundParameters.ContainsKey('MaxParallelJobs') -and $global:Settings -and $global:Settings.Performance -and $global:Settings.Performance.MaxConcurrentJobs) {
            $MaxParallelJobs = [Math]::Max(1, [int]$global:Settings.Performance.MaxConcurrentJobs)
        }
    } catch {}

    $progressForm = New-Object System.Windows.Forms.Form
    $progressForm.Text = "Updating Centralized User Logon Database"
    $progressForm.Size = New-Object System.Drawing.Size(500, 200)
    $progressForm.StartPosition = "CenterScreen"
    $progressForm.FormBorderStyle = "FixedDialog"
    $progressForm.MaximizeBox = $false
    $progressForm.MinimizeBox = $false
    $progressForm.TopMost = $true

    $progressLabel = New-Object System.Windows.Forms.Label
    $progressLabel.Location = New-Object System.Drawing.Point(10, 20)
    $progressLabel.Size = New-Object System.Drawing.Size(470, 40)
    $progressLabel.Text = "Getting active computers from Active Directory..."
    $progressForm.Controls.Add($progressLabel)

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(10, 70)
    $progressBar.Size = New-Object System.Drawing.Size(470, 30)
    $progressBar.Style = "Continuous"
    $progressForm.Controls.Add($progressBar)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(10, 110)
    $statusLabel.Size = New-Object System.Drawing.Size(470, 40)
    $statusLabel.Text = "Starting CSV collection..."
    $progressForm.Controls.Add($statusLabel)

    $progressForm.Add_Shown({ $progressForm.Activate() })
    $progressForm.Show()
    [System.Windows.Forms.Application]::DoEvents()

    try {
        Initialize-CentralizedUserLogonCSV -Force:$Force
        $centralizedCSVPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"

        if ($PSCmdlet.ParameterSetName -eq "SpecificComputer") {
            $computers = @([PSCustomObject]@{
                Name      = $ComputerName
                LastLogon = Get-Date
            })
        }
        else {
            $progressLabel.Text = "Getting active computers from AD..."
            [System.Windows.Forms.Application]::DoEvents()

            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                $searcher.PageSize = 1000
                $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
                $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null

                $allComputers = $searcher.FindAll()

                $computers = $allComputers | ForEach-Object {
                    $lastLogon = 0
                    if ($_.Properties["lastLogonTimestamp"].Count -gt 0) {
                        $lastLogon = [DateTime]::FromFileTime([Int64]::Parse($_.Properties["lastLogonTimestamp"][0].ToString()))
                    }

                    $os = ""
                    if ($_.Properties["operatingSystem"].Count -gt 0) {
                        $os = $_.Properties["operatingSystem"][0].ToString()
                    }

                    if ($os -match "Windows" -and $lastLogon -gt (Get-Date).AddDays(-30)) {
                        [PSCustomObject]@{
                            Name      = $_.Properties["name"][0].ToString()
                            LastLogon = $lastLogon
                        }
                    }
                } | Sort-Object LastLogon -Descending | Select-Object -First $maxComputers
            }
            catch {
                Write-Log -Message "Error getting computers from AD: $_" -Level "Error"
                $computers = @()
            }
        }

        $totalComputers = $computers.Count
        $progressBar.Maximum = $totalComputers
        $progressBar.Value = 0
        $statusLabel.Text = "Found $totalComputers computers to scan"
        [System.Windows.Forms.Application]::DoEvents()

        $allEntries = [System.Collections.ArrayList]::new()
        $processedCount = 0
        $successCount = 0
        $errorCount = 0

        # Script block executed inside each background job
        $computerProcessingScript = {
            param($ComputerName)

            try {
                $isOnline = $false
                try {
                    $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
                    $isOnline = $ping
                } catch {}

                if (-not $isOnline) {
                    return @{
                        ComputerName = $ComputerName
                        IsOnline     = $false
                        Success      = $false
                        Entries      = @()
                        Error        = "Computer is offline"
                    }
                }

                $csvPath = "\\$ComputerName\c$\ProgramData\IT\Logs\UserLogon.csv"
                if (Test-Path $csvPath) {
                    try {
                        $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

                        $processedEntries = foreach ($entry in $csvData) {
                            if (-not $entry.ComputerName) {
                                $entry | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $ComputerName -Force
                            }

                            if (-not $entry.LastSeen) {
                                $timestamp = if ($entry.LogonTime) { $entry.LogonTime } else { (Get-Date).ToString() }
                                $entry | Add-Member -MemberType NoteProperty -Name "LastSeen" -Value $timestamp -Force
                            }

                            if (-not $entry.Source) {
                                $entry | Add-Member -MemberType NoteProperty -Name "Source" -Value "ComputerCSV" -Force
                            }

                            $entry
                        }

                        return @{
                            ComputerName = $ComputerName
                            IsOnline     = $true
                            Success      = $true
                            Entries      = $processedEntries
                            Error        = $null
                        }
                    }
                    catch {
                        return @{
                            ComputerName = $ComputerName
                            IsOnline     = $true
                            Success      = $false
                            Entries      = @()
                            Error        = "Error importing CSV: $_"
                        }
                    }
                }
                else {
                    # No CSV -- attempt live quser lookup
                    try {
                        $quser = quser /server:$ComputerName 2>&1
                        if ($quser -is [System.Management.Automation.ErrorRecord]) {
                            return @{
                                ComputerName = $ComputerName
                                IsOnline     = $true
                                Success      = $false
                                Entries      = @()
                                Error        = "Error running quser: $quser"
                            }
                        }

                        $users = @()
                        $userLines = $quser | Select-Object -Skip 1
                        foreach ($line in $userLines) {
                            try {
                                $line = $line -replace '\s{2,}', ',' -replace '^\s+','' -replace '\s+$',''
                                $fields = $line.Split(',')

                                if ($fields.Count -ge 2) {
                                    $username = $fields[0].Trim()

                                    $entry = [PSCustomObject]@{
                                        Username     = $username
                                        ComputerName = $ComputerName
                                        LastSeen     = (Get-Date).ToString()
                                        Source       = "QUser"
                                        Action       = "Logged On"
                                        IPAddress    = ""
                                        UserFullName = ""
                                        LogonTime    = (Get-Date).ToString()
                                        SessionID    = ""
                                        DomainName   = ""
                                    }

                                    $users += $entry
                                }
                            }
                            catch {
                                # Skip unparseable lines
                            }
                        }

                        return @{
                            ComputerName = $ComputerName
                            IsOnline     = $true
                            Success      = $true
                            Entries      = $users
                            Error        = $null
                        }
                    }
                    catch {
                        return @{
                            ComputerName = $ComputerName
                            IsOnline     = $true
                            Success      = $false
                            Entries      = @()
                            Error        = "Error getting users: $_"
                        }
                    }
                }
            }
            catch {
                return @{
                    ComputerName = $ComputerName
                    IsOnline     = $false
                    Success      = $false
                    Entries      = @()
                    Error        = "General error: $_"
                }
            }
        }

        # Process computers in parallel via background jobs
        $jobs = @{}
        $currentIndex = 0

        while ($currentIndex -lt $totalComputers -or $jobs.Count -gt 0) {
            # Launch jobs up to the concurrency limit
            while ($jobs.Count -lt $MaxParallelJobs -and $currentIndex -lt $totalComputers) {
                $computer = $computers[$currentIndex]
                $computerName = $computer.Name

                $statusLabel.Text = "Starting job for $computerName ($($currentIndex + 1) of $totalComputers)"
                [System.Windows.Forms.Application]::DoEvents()

                $job = Start-Job -ScriptBlock $computerProcessingScript -ArgumentList $computerName
                $jobs[$job.Id] = @{
                    Job          = $job
                    ComputerName = $computerName
                    StartTime    = Get-Date
                }

                $currentIndex++
            }

            # Harvest finished jobs
            $completedJobIds = @($jobs.Keys | Where-Object { $jobs[$_].Job.State -ne 'Running' })

            foreach ($jobId in $completedJobIds) {
                $jobInfo = $jobs[$jobId]
                $computerName = $jobInfo.ComputerName

                try {
                    $opStart = Get-Date
                    $result = Receive-Job -Id $jobId -ErrorAction Stop

                    $processedCount++
                    $progressBar.Value = $processedCount

                    if ($result.Success) {
                        $successCount++
                        $statusLabel.Text = "Processed $computerName - Success ($processedCount of $totalComputers)"

                        if ($result.Entries -and $result.Entries.Count -gt 0) {
                            $allEntries.AddRange($result.Entries)
                        }
                        $durMs = [int]((Get-Date) - $opStart).TotalMilliseconds
                        try { Write-LogEvent -Operation 'UserLocationIndexUpdate' -EventId 4001 -Context @{ computer=$computerName; entries=($result.Entries.Count) } -DurationMs $durMs } catch {}
                    }
                    else {
                        $errorCount++
                        $statusLabel.Text = "Processed $computerName - Error: $($result.Error)"
                        Write-Log -Message "Error processing $computerName`: $($result.Error)" -Level "Warning"
                    }
                }
                catch {
                    $processedCount++
                    $errorCount++
                    $progressBar.Value = $processedCount
                    $statusLabel.Text = "Error receiving job for $computerName`: $_"
                    Write-Log -Message "Error receiving job for $computerName`: $_" -Level "Error"
                }

                Remove-Job -Id $jobId -Force
                $jobs.Remove($jobId)

                [System.Windows.Forms.Application]::DoEvents()
            }

            # Kill jobs that have exceeded the 2-minute timeout
            $timeoutJobIds = @($jobs.Keys | Where-Object {
                $jobs[$_].Job.State -eq 'Running' -and
                ((Get-Date) - $jobs[$_].StartTime).TotalMinutes -gt 2
            })

            foreach ($jobId in $timeoutJobIds) {
                $jobInfo = $jobs[$jobId]
                $computerName = $jobInfo.ComputerName

                $processedCount++
                $errorCount++
                $progressBar.Value = $processedCount
                $statusLabel.Text = "Timeout processing $computerName"
                Write-Log -Message "Timeout processing $computerName" -Level "Warning"

                Stop-Job -Id $jobId -ErrorAction SilentlyContinue
                Remove-Job -Id $jobId -Force -ErrorAction SilentlyContinue
                $jobs.Remove($jobId)

                [System.Windows.Forms.Application]::DoEvents()
            }

            Start-Sleep -Milliseconds 100
        }

        $statusLabel.Text = "Processing completed. Updating database..."
        [System.Windows.Forms.Application]::DoEvents()

        # Merge new entries with existing data, de-duplicate, and persist
        $existingEntries = @()
        if (Test-Path $centralizedCSVPath) {
            try {
                $existingEntries = Import-Csv -Path $centralizedCSVPath -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Error reading existing centralized CSV: $_" -Level "Warning"
            }
        }

        $combinedEntries = $existingEntries + $allEntries

        $uniqueEntries = $combinedEntries | Group-Object -Property Username, ComputerName, LastSeen | ForEach-Object {
            $_.Group[0]
        }

        $sortedEntries = $uniqueEntries | Sort-Object -Property LastSeen -Descending

        try {
            $sortedEntries | Export-Csv -Path $centralizedCSVPath -NoTypeInformation -Encoding UTF8 -Force

            $statusLabel.Text = "Database updated successfully. Processed $processedCount computers ($successCount successful, $errorCount errors)."
            Write-Log -Message "Centralized user logon database updated with $($sortedEntries.Count) entries" -Level "Info"

            # Refresh the in-memory cache
            $script:CentralizedDBCache = $sortedEntries
            $script:CentralizedDBCacheTime = Get-Date
        }
        catch {
            $statusLabel.Text = "Error updating database: $_"
            Write-Log -Message "Error writing to centralized user logon CSV: $_" -Level "Error"
        }

        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Seconds 3
        $progressForm.Close()

        return $true
    }
    catch {
        Write-Log -Message "Error updating centralized user logon CSV: $_" -Level "Error"
        $statusLabel.Text = "Error: $_"
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Seconds 3
        $progressForm.Close()
        return $false
    }
}

function Show-CentralizedUserLogonCSV {
    <#
    .SYNOPSIS
        Displays the centralized user logon database in a WinForms dialog.
    .DESCRIPTION
        Opens a searchable ListView window showing all entries from
        CentralizedUserLogon.csv.  Supports searching, refreshing, exporting
        to CSV, and triggering a full database update from within the UI.
    .OUTPUTS
        None (UI dialog).
    .EXAMPLE
        Show-CentralizedUserLogonCSV
        Opens the centralized database viewer.
    #>
    [CmdletBinding()]
    param()

    try {
        $csvPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"

        if (-not (Test-Path $csvPath)) {
            Initialize-CentralizedUserLogonCSV

            if (-not (Test-Path $csvPath)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Centralized User Logon database not found.",
                    "Database Missing",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
        }

        try {
            $csvData = Import-Csv -Path $csvPath -ErrorAction Stop

            if ($null -eq $csvData -or $csvData.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Centralized User Logon database is empty. Please update the database.",
                    "Empty Database",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                return
            }

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Centralized User Logon Database"
            $form.Size = New-Object System.Drawing.Size(900, 600)
            $form.StartPosition = "CenterScreen"
            $form.MinimizeBox = $true
            $form.MaximizeBox = $true

            $listView = New-Object System.Windows.Forms.ListView
            $listView.View = [System.Windows.Forms.View]::Details
            $listView.FullRowSelect = $true
            $listView.GridLines = $true
            $listView.Location = New-Object System.Drawing.Point(10, 10)
            $listView.Size = New-Object System.Drawing.Size(865, 480)
            $listView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

            $headers = $csvData[0].PSObject.Properties.Name
            foreach ($header in $headers) {
                $width = switch ($header) {
                    "Username"     { 120 }
                    "LastSeen"     { 150 }
                    "LogonTime"    { 150 }
                    "ComputerName" { 120 }
                    "IPAddress"    { 120 }
                    "Action"       { 80 }
                    "DomainName"   { 100 }
                    "UserFullName" { 200 }
                    "Source"       { 80 }
                    default        { 120 }
                }

                $listView.Columns.Add($header, $width) | Out-Null
            }

            foreach ($row in $csvData) {
                $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                for ($i = 1; $i -lt $headers.Count; $i++) {
                    $item.SubItems.Add($row.($headers[$i])) | Out-Null
                }

                $listView.Items.Add($item) | Out-Null
            }

            $statusLabel = New-Object System.Windows.Forms.Label
            $statusLabel.Location = New-Object System.Drawing.Point(10, 500)
            $statusLabel.Size = New-Object System.Drawing.Size(865, 20)
            $statusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
            $statusLabel.Text = "Total entries: $($csvData.Count) | Last Updated: $((Get-UserLocationIndexLastUpdate).ToString('yyyy-MM-dd HH:mm:ss'))"

            $searchPanel = New-Object System.Windows.Forms.Panel
            $searchPanel.Location = New-Object System.Drawing.Point(10, 520)
            $searchPanel.Size = New-Object System.Drawing.Size(865, 35)
            $searchPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

            $searchLabel = New-Object System.Windows.Forms.Label
            $searchLabel.Location = New-Object System.Drawing.Point(0, 8)
            $searchLabel.Size = New-Object System.Drawing.Size(60, 20)
            $searchLabel.Text = "Search:"
            $searchPanel.Controls.Add($searchLabel)

            $searchBox = New-Object System.Windows.Forms.TextBox
            $searchBox.Location = New-Object System.Drawing.Point(65, 5)
            $searchBox.Size = New-Object System.Drawing.Size(200, 20)
            $searchPanel.Controls.Add($searchBox)

            $searchButton = New-Object System.Windows.Forms.Button
            $searchButton.Location = New-Object System.Drawing.Point(275, 4)
            $searchButton.Size = New-Object System.Drawing.Size(75, 23)
            $searchButton.Text = "Search"
            $searchPanel.Controls.Add($searchButton)

            $refreshButton = New-Object System.Windows.Forms.Button
            $refreshButton.Location = New-Object System.Drawing.Point(360, 4)
            $refreshButton.Size = New-Object System.Drawing.Size(75, 23)
            $refreshButton.Text = "Refresh"
            $searchPanel.Controls.Add($refreshButton)

            $exportButton = New-Object System.Windows.Forms.Button
            $exportButton.Location = New-Object System.Drawing.Point(445, 4)
            $exportButton.Size = New-Object System.Drawing.Size(100, 23)
            $exportButton.Text = "Export to CSV"
            $searchPanel.Controls.Add($exportButton)

            $updateButton = New-Object System.Windows.Forms.Button
            $updateButton.Location = New-Object System.Drawing.Point(555, 4)
            $updateButton.Size = New-Object System.Drawing.Size(150, 23)
            $updateButton.Text = "Update Database"
            $searchPanel.Controls.Add($updateButton)

            $searchFunction = {
                $searchText = $searchBox.Text.Trim()
                $listView.Items.Clear()

                if ([string]::IsNullOrEmpty($searchText)) {
                    foreach ($row in $csvData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    # Auto-select single match for quick keyboard workflows
                    if ($listView.Items.Count -eq 1) {
                        try {
                            $listView.Items[0].Selected = $true
                            $listView.Items[0].Focused = $true
                            $listView.EnsureVisible(0)
                            $listView.Select()
                            $listView.Focus()
                        } catch {}
                    }

                    $statusLabel.Text = "Total entries: $($csvData.Count) | Last Updated: $((Get-UserLocationIndexLastUpdate).ToString('yyyy-MM-dd HH:mm:ss'))"
                }
                else {
                    $filteredData = $csvData | Where-Object {
                        $match = $false
                        foreach ($prop in $_.PSObject.Properties) {
                            if ($prop.Value -like "*$searchText*") {
                                $match = $true
                                break
                            }
                        }
                        $match
                    }

                    foreach ($row in $filteredData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    # Auto-select single match for quick keyboard workflows
                    if ($listView.Items.Count -eq 1) {
                        try {
                            $listView.Items[0].Selected = $true
                            $listView.Items[0].Focused = $true
                            $listView.EnsureVisible(0)
                            $listView.Select()
                            $listView.Focus()
                        } catch {}
                    }

                    $statusLabel.Text = "Filtered entries: $($listView.Items.Count) of $($csvData.Count) | Last Updated: $((Get-UserLocationIndexLastUpdate).ToString('yyyy-MM-dd HH:mm:ss'))"
                }
            }

            $searchButton.Add_Click($searchFunction)
            $searchBox.Add_KeyDown({
                if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
                    $searchFunction.Invoke()
                }
            })

            $refreshButton.Add_Click({
                try {
                    $script:csvData = Import-Csv -Path $csvPath -ErrorAction Stop
                    $listView.Items.Clear()

                    foreach ($row in $script:csvData) {
                        $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                        for ($i = 1; $i -lt $headers.Count; $i++) {
                            $item.SubItems.Add($row.($headers[$i])) | Out-Null
                        }

                        $listView.Items.Add($item) | Out-Null
                    }

                    $statusLabel.Text = "Total entries: $($script:csvData.Count) | Last Updated: $((Get-UserLocationIndexLastUpdate).ToString('yyyy-MM-dd HH:mm:ss'))"
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Error refreshing data: $_",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            })

            $exportButton.Add_Click({
                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export CSV Data"
                $saveFileDialog.FileName = "UserLogon_Export.csv"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    try {
                        $csvData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
                        [System.Windows.Forms.MessageBox]::Show(
                            "Data exported successfully to $($saveFileDialog.FileName).",
                            "Export Successful",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Information
                        )
                    }
                    catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Error exporting data: $_",
                            "Export Error",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                    }
                }
            })

            $updateButton.Add_Click({
                try {
                    # Hide viewer while the progress dialog runs
                    $form.Hide()

                    $result = Update-CentralizedUserLogonCSV -Force

                    if ($result) {
                        $script:csvData = Import-Csv -Path $csvPath -ErrorAction Stop
                        $listView.Items.Clear()

                        foreach ($row in $script:csvData) {
                            $item = New-Object System.Windows.Forms.ListViewItem($row.($headers[0]))

                            for ($i = 1; $i -lt $headers.Count; $i++) {
                                $item.SubItems.Add($row.($headers[$i])) | Out-Null
                            }

                            $listView.Items.Add($item) | Out-Null
                        }

                        $statusLabel.Text = "Total entries: $($script:csvData.Count) | Last Updated: $((Get-UserLocationIndexLastUpdate).ToString('yyyy-MM-dd HH:mm:ss'))"
                        $form.Show()
                    }
                    else {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Error updating database. Check the logs for details.",
                            "Update Error",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                        $form.Show()
                    }
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Error updating database: $_",
                        "Update Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                    $form.Show()
                }
            })

            $form.Controls.Add($listView)
            $form.Controls.Add($statusLabel)
            $form.Controls.Add($searchPanel)

            $form.ShowDialog() | Out-Null
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error reading CSV file: $_",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
    catch {
        Write-Log -Message "Error in Show-CentralizedUserLogonCSV: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Get-IndexedUsersForComputer {
    <#
    .SYNOPSIS
        Returns indexed users for a given computer from the centralized database.
    .DESCRIPTION
        Compatibility wrapper that queries CentralizedUserLogon.csv for all
        entries matching the specified computer name.  Falls back to a live
        Get-LoggedInUsers call when the centralized database is unavailable.
    .PARAMETER ComputerName
        The computer name to look up.
    .OUTPUTS
        [PSCustomObject[]] with a UserName property.
    .EXAMPLE
        Get-IndexedUsersForComputer -ComputerName "PC01"
        Returns all users previously logged on to PC01.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        $centralizedCsvPath = Join-Path -Path $global:AppConfig.DataPath -ChildPath "CentralizedUserLogon.csv"
        if (Test-Path $centralizedCsvPath) {
            try {
                $csvData = Import-Csv -Path $centralizedCsvPath -ErrorAction Stop
                return $csvData | Where-Object { $_.ComputerName -eq $ComputerName } |
                    Select-Object -Property @{Name="UserName"; Expression={$_.Username}}
    }
    catch {
                Write-Log -Message "Error reading centralized CSV for $ComputerName`: $_" -Level "Warning"
                return @()
            }
        }
        else {
            Write-Log -Message "Centralized user logon database not found" -Level "Verbose"
            # Live lookup as last resort
            $liveUsers = Get-LoggedInUsers -ComputerName $ComputerName
            if ($liveUsers -and $liveUsers.Count -gt 0) {
                return $liveUsers | Select-Object -Property @{Name="UserName"; Expression={$_.Username}}
            }
            return @()
        }
    }
    catch {
        Write-Log -Message "Error in Get-IndexedUsersForComputer: $_" -Level "Error"
        return @()
    }
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Initialize-UserLocationIndex',
    'Update-UserLocationIndex',
    'Get-UserLocationIndexAge',
    'Get-LoggedInUsers',
    'Get-UserLocationIndexLastUpdate',
    'Set-UserLocationIndexLastUpdate',
    'Get-UserLocationForUsername',
    'Get-UserLocationFromCentralizedDB',
    'Test-ComputerOnline',
    'Show-UserLocationIndex',
    'Get-UserLocation',
    'Show-ComputerUserLogonCSV',
    'Initialize-CentralizedUserLogonCSV',
    'Update-CentralizedUserLogonCSV',
    'Show-CentralizedUserLogonCSV',
    'Get-IndexedUsersForComputer'
)
