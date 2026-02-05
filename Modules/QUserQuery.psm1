#Requires -Version 5.1

<#
.SYNOPSIS
    QUserQuery module for querying and caching remote user session data.
.DESCRIPTION
    Provides functions to query logged-on user sessions via quser.exe on remote
    computers, cache results with thread-safe locking, track historical session
    data, and combine session information from multiple sources (QUser, PDQ
    Inventory).
.NOTES
    Module : QUserQuery
    Author : ADapp Team
#>

# Ensure the module-level lock object exists for thread-safe cache access
if (-not $script:QUserCacheLock) { $script:QUserCacheLock = New-Object object }

#region Functions

function Get-QUserInfo {
    <#
    .SYNOPSIS
        Queries logged-on user sessions on a remote computer via quser.exe.
    .DESCRIPTION
        Runs quser.exe against a remote computer with a configurable timeout to
        retrieve active user sessions.  An optional Invoke-Command (WinRM)
        fallback can be enabled when the direct quser call returns no output.
        A fast ICMP ping check is performed first, but the query proceeds even
        when ping fails because some hosts block ICMP.
    .PARAMETER ComputerName
        The hostname or FQDN of the remote computer to query.
    .PARAMETER TimeoutSeconds
        Maximum number of seconds to wait for the quser process to complete.
        Defaults to 10.
    .PARAMETER EnableInvokeCommandFallback
        When specified, allows falling back to Invoke-Command (WinRM) if the
        direct quser call returns no output.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of parsed session objects, or an empty array on failure.
    .EXAMPLE
        Get-QUserInfo -ComputerName 'SERVER01'
        Queries active user sessions on SERVER01 with a 10-second timeout.
    .EXAMPLE
        Get-QUserInfo -ComputerName 'PC042' -TimeoutSeconds 5 -EnableInvokeCommandFallback
        Queries PC042 with a 5-second timeout and falls back to WinRM if needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [int]$TimeoutSeconds = 10,

        [switch]$EnableInvokeCommandFallback
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return @() }

    try {
        # Fast online check to avoid long waits on offline machines
        $isOnline = $false
        if ($ComputerName) {
            $target = $ComputerName.Split('.')[0].Trim()
            try {
                # Prefer Test-Connection; fallback to native ping.exe
                $isOnline = Test-Connection -ComputerName $target -Count 1 -Quiet -TimeoutSeconds 2 -ErrorAction SilentlyContinue
                if (-not $isOnline) {
                    $pingCmd = Get-Command ping.exe -ErrorAction SilentlyContinue
                    if ($pingCmd) {
                        $null = & $pingCmd.Source -n 1 -w 1000 $target 2>$null
                        if ($LASTEXITCODE -eq 0) { $isOnline = $true }
                    }
                }
            }
            catch { $isOnline = $false }

            if ($isOnline) {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Get-QUserInfo: Computer $ComputerName is online (ping successful), querying quser" -Level "Info"
                }
            }
            else {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Get-QUserInfo: Computer $ComputerName ping failed, but will try quser anyway (ICMP may be blocked)" -Level "Info"
                }
            }
        }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Getting quser info for $ComputerName" -Level "Verbose"
        }

        if ($TimeoutSeconds -lt 1) { $TimeoutSeconds = 1 }

        # Run quser with a hard timeout so offline hosts don't stall the UI / pipeline
        $output = $null
        $timedOut = $false

        $invokeQuserWithTimeout = {
            param([string]$Server, [int]$TimeoutSec)
            $exe = $null
            try { $exe = (Get-Command quser.exe -ErrorAction SilentlyContinue).Source } catch { $exe = $null }
            if ([string]::IsNullOrWhiteSpace($exe)) { $exe = "quser.exe" }

            $psi               = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName      = $exe
            $psi.Arguments     = "/server:$Server"
            $psi.UseShellExecute       = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow         = $true

            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $psi

            try {
                $null = $p.Start()
                $ms = [Math]::Max(1000, ($TimeoutSec * 1000))
                if (-not $p.WaitForExit($ms)) {
                    try { $p.Kill() } catch {}
                    return [PSCustomObject]@{ TimedOut = $true; Output = $null; Error = $null }
                }

                $stdOut = $null
                $stdErr = $null
                try { $stdOut = $p.StandardOutput.ReadToEnd() } catch { $stdOut = $null }
                try { $stdErr = $p.StandardError.ReadToEnd() } catch { $stdErr = $null }

                $lines = @()
                if (-not [string]::IsNullOrWhiteSpace($stdOut)) {
                    $lines = @($stdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                }

                return [PSCustomObject]@{ TimedOut = $false; Output = $lines; Error = $stdErr }
            }
            finally {
                try { $p.Dispose() } catch {}
            }
        }

        try {
            $r = & $invokeQuserWithTimeout -Server $ComputerName -TimeoutSec $TimeoutSeconds
            $timedOut = [bool]$r.TimedOut
            $output = $r.Output
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                if ($timedOut) {
                    Write-Log -Message "Get-QUserInfo: quser /server:$ComputerName timed out after ${TimeoutSeconds}s" -Level "Info"
                }
                else {
                    $lineCount = if ($output) { $output.Count } else { 0 }
                    Write-Log -Message "Get-QUserInfo: quser /server:$ComputerName returned $lineCount lines" -Level "Info"
                }
            }
        }
        catch {
            $output = $null
        }

        # Optionally try Invoke-Command when direct quser returned nothing
        # Requires WinRM; disabled by default to avoid long hangs where remoting is blocked
        $allowInvokeFallback = $false
        try {
            if ($global:Settings -and $global:Settings.QUser -and ($null -ne $global:Settings.QUser.UseInvokeCommandFallback)) {
                $allowInvokeFallback = [bool]$global:Settings.QUser.UseInvokeCommandFallback
            }
        } catch { $allowInvokeFallback = $false }
        if ($EnableInvokeCommandFallback) { $allowInvokeFallback = $true }

        if (-not $output -and -not $timedOut -and $allowInvokeFallback) {
            try {
                if (Get-Command Invoke-Command -ErrorAction SilentlyContinue) {
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log -Message "Get-QUserInfo: quser /server:$ComputerName returned no output; trying Invoke-Command fallback" -Level "Info"
                    }
                    $so = $null
                    try { $so = New-PSSessionOption -OperationTimeout ($TimeoutSeconds * 1000) } catch { $so = $null }
                    $output = Invoke-Command -ComputerName $ComputerName -SessionOption $so -ScriptBlock { quser 2>$null } -ErrorAction Stop
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        $lineCount = if ($output) { $output.Count } else { 0 }
                        Write-Log -Message "Get-QUserInfo: Invoke-Command quser returned $lineCount lines for $ComputerName" -Level "Info"
                    }
                }
            }
            catch {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Get-QUserInfo: Both quser methods failed for $ComputerName" -Level "Info"
                }
                return @()
            }
        }
        elseif (-not $output -and $timedOut) {
            # Skip remoting fallback when quser already timed out to avoid compounding delay
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Get-QUserInfo: quser timed out for $ComputerName; skipping Invoke-Command fallback" -Level "Info"
            }
        }

        if ($output) {
            $parsed = Parse-QUserOutput -QUserOutput $output -ComputerName $ComputerName
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                $parsedCount = @($parsed).Count
                Write-Log -Message "Get-QUserInfo: Parsed $parsedCount sessions from quser output for $ComputerName" -Level "Info"
            }
            return $parsed
        }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Get-QUserInfo: No quser output for $ComputerName" -Level "Info"
        }
        return @()
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error getting quser info for ${ComputerName}: $_" -Level "Warning"
        }
        return @()
    }
}

function Get-QUserInfoWithCache {
    <#
    .SYNOPSIS
        Retrieves user session data for a computer, using a timed in-memory cache.
    .DESCRIPTION
        Wraps Get-QUserInfo with a thread-safe in-memory cache keyed by computer
        name.  If cached data exists and is younger than CacheAgeMinutes the
        cached result is returned immediately, avoiding redundant quser calls.
        Fresh results are stored back into the cache and historical tracking is
        updated.
    .PARAMETER ComputerName
        The hostname or FQDN of the remote computer to query.
    .PARAMETER CacheAgeMinutes
        Maximum age in minutes before cached data is considered stale.
        Defaults to 5.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of session objects, or an empty array on failure.
    .EXAMPLE
        Get-QUserInfoWithCache -ComputerName 'SERVER01'
        Returns cached sessions if available and fresh, otherwise queries live.
    .EXAMPLE
        Get-QUserInfoWithCache -ComputerName 'PC042' -CacheAgeMinutes 2
        Uses a 2-minute cache TTL instead of the default 5 minutes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [int]$CacheAgeMinutes = 5
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return @() }

    try {
        # Initialize cache if it doesn't exist
        if (-not $global:QUserCache) {
            Initialize-QUserCache
        }

        $computerKey = $ComputerName.ToUpperInvariant()
        $now = Get-Date

        # Check if we have recent cached data (thread-safe)
        $useCached = $false
        $cachedSessions = $null
        $cacheAgeLogged = $null
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            if ($global:QUserCache.Data.ContainsKey($computerKey)) {
                $cachedData = $global:QUserCache.Data[$computerKey]
                if ($cachedData -and $cachedData.Timestamp) {
                    $cacheAge = ($now - $cachedData.Timestamp).TotalMinutes
                    if ($cacheAge -lt $CacheAgeMinutes) {
                        $useCached = $true
                        $cachedSessions = $cachedData.Sessions
                        $cacheAgeLogged = [math]::Round($cacheAge, 1)
                    }
                }
            }
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        if ($useCached) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Using cached quser data for $ComputerName (age: $cacheAgeLogged minutes)" -Level "Verbose"
            }
            return $cachedSessions
        }

        # Cache is stale or doesn't exist, get fresh data
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Querying fresh quser data for $ComputerName" -Level "Verbose"
        }

        # Determine timeout from settings if available
        $timeout = 10
        try {
            if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.TimeoutSeconds) {
                $timeout = [int]$global:Settings.QUser.TimeoutSeconds
            }
        } catch { $timeout = 10 }
        if ($timeout -lt 1) { $timeout = 1 }

        $sessions = Get-QUserInfo -ComputerName $ComputerName -TimeoutSeconds $timeout

        # Cache the results (thread-safe)
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            $global:QUserCache.Data[$computerKey] = @{
                Sessions  = $sessions
                Timestamp = $now
            }
            $global:QUserCache.LastUpdated = $now
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        # Update historical tracking
        Update-QUserHistoricalData -ComputerName $ComputerName -Sessions $sessions

        return $sessions
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error getting quser info with cache for ${ComputerName}: $_" -Level "Warning"
        }
        return @()
    }
}

function Initialize-QUserCache {
    <#
    .SYNOPSIS
        Creates or resets the global QUser session cache.
    .DESCRIPTION
        Initialises the global $QUserCache hashtable with empty data structures
        for session data, user-to-computer mappings, and historical tracking.
        After initialisation, any persisted historical data is loaded from disk.
    .OUTPUTS
        None.  The function modifies $global:QUserCache in place.
    .EXAMPLE
        Initialize-QUserCache
        Resets the QUser cache and reloads historical data from disk.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:QUserCacheLock) { $script:QUserCacheLock = New-Object object }
    try {
        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
        $global:QUserCache = @{
            Data             = @{}
            LastUpdated      = $null
            UserToComputers  = @{}
            HistoricalData   = @{
                ComputerSessions = @{}
                UserSessions     = @{}
                LastCleanup      = Get-Date
            }
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

    # Load historical data from file if it exists
    Load-QUserHistoricalData
}

function Update-QUserHistoricalData {
    <#
    .SYNOPSIS
        Records session data into the historical tracking structures.
    .DESCRIPTION
        Accepts a computer name and its current sessions, updates the
        user-to-computer mapping, and (when historical tracking is enabled
        in settings) maintains per-computer and per-user session history with
        first-seen / last-seen timestamps and occurrence counts.
    .PARAMETER ComputerName
        The hostname whose session data is being recorded.
    .PARAMETER Sessions
        An array of session objects returned by Get-QUserInfo or Parse-QUserOutput.
    .OUTPUTS
        None.  The function modifies $global:QUserCache.HistoricalData in place.
    .EXAMPLE
        Update-QUserHistoricalData -ComputerName 'SERVER01' -Sessions $sessions
        Updates historical tracking for SERVER01 with the supplied session list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [array]$Sessions
    )

    if (-not $global:QUserCache.HistoricalData) { return }

    # Check if historical tracking is enabled in settings
    $historicalEnabled = $true
    if ($global:Settings -and $global:Settings.QUser -and ($null -ne $global:Settings.QUser.EnableHistoricalTracking)) {
        $historicalEnabled = $global:Settings.QUser.EnableHistoricalTracking
    }

    $computerKey = $ComputerName.ToUpperInvariant()
    $now = Get-Date

    try {
        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
        # Initialize computer history if not exists
        if (-not $global:QUserCache.HistoricalData.ComputerSessions.ContainsKey($computerKey)) {
            $global:QUserCache.HistoricalData.ComputerSessions[$computerKey] = @()
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

    # Build list of current users on this computer
    $currentUsers = @{}
    foreach ($session in $Sessions) {
        if ($session -and -not [string]::IsNullOrWhiteSpace($session.Username)) {
            $currentUsers[$session.Username.ToUpperInvariant()] = $true
        }
    }

    # Clean up UserToComputers mapping -- remove this computer from users no longer logged in
    try {
        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
        foreach ($userKey in @($global:QUserCache.UserToComputers.Keys)) {
            if ($global:QUserCache.UserToComputers[$userKey] -contains $ComputerName) {
                if (-not $currentUsers.ContainsKey($userKey)) {
                    # User is no longer logged in; remove this computer from their list
                    $global:QUserCache.UserToComputers[$userKey] = @($global:QUserCache.UserToComputers[$userKey] | Where-Object { $_ -ne $ComputerName })
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log -Message "Removed computer $ComputerName from user mapping for $userKey (no longer logged in)" -Level "Verbose"
                    }
                    # If user has no computers left, remove the empty entry
                    if ($global:QUserCache.UserToComputers[$userKey].Count -eq 0) {
                        $global:QUserCache.UserToComputers.Remove($userKey)
                    }
                }
            }
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

    foreach ($session in $Sessions) {
        if (-not $session -or [string]::IsNullOrWhiteSpace($session.Username)) { continue }

        $userKey = $session.Username.ToUpperInvariant()

        # Always update the user-to-computers mapping regardless of historical tracking setting
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            if (-not $global:QUserCache.UserToComputers.ContainsKey($userKey)) {
                $global:QUserCache.UserToComputers[$userKey] = @()
            }
            if ($global:QUserCache.UserToComputers[$userKey] -notcontains $ComputerName) {
                $global:QUserCache.UserToComputers[$userKey] += $ComputerName
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Added user $($session.Username) to computer mapping for $ComputerName" -Level "Verbose"
                }
            }
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        # Only do detailed historical tracking if enabled
        if ($historicalEnabled) {
            # Create historical session record
            $historicalSession = [PSCustomObject]@{
                Username     = $session.Username
                ComputerName = $ComputerName
                SessionName  = $session.SessionName
                SessionId    = $session.SessionId
                State        = $session.State
                IdleTime     = $session.IdleTime
                LogonTime    = $session.LogonTime
                FirstSeen    = $now
                LastSeen     = $now
                SeenCount    = 1
            }

            # Update historical structures (thread-safe)
            try {
                [System.Threading.Monitor]::Enter($script:QUserCacheLock)
                # Helper to safely get DateTime from potentially corrupted data
                function Get-SafeDateTime {
                    param([object]$Value)
                    if ($null -eq $Value) { return $null }
                    if ($Value -is [DateTime]) { return $Value }
                    if ($Value -is [Array] -and $Value.Count -gt 0) {
                        $first = $Value[0]
                        if ($first -is [DateTime]) { return $first }
                        if ($first -is [String]) {
                            $parsed = $null
                            if ([DateTime]::TryParse($first, [ref]$parsed)) { return $parsed }
                        }
                    }
                    if ($Value -is [String]) {
                        $parsed = $null
                        if ([DateTime]::TryParse($Value, [ref]$parsed)) { return $parsed }
                    }
                    return $null
                }

                # Check if we already have a recent record for this user/computer combination
                $existingRecord = $global:QUserCache.HistoricalData.ComputerSessions[$computerKey] |
                    Where-Object {
                        $_.Username.ToUpperInvariant() -eq $userKey -and
                        ($lastSeen = Get-SafeDateTime -Value $_.LastSeen) -ne $null -and
                        ($now - $lastSeen).TotalHours -lt 24
                    } |
                    Select-Object -First 1
                if ($existingRecord) {
                    # Update existing record
                    $existingRecord.LastSeen = $now
                    $existingRecord.SeenCount++
                    $existingRecord.State = $session.State
                    $existingRecord.SessionName = $session.SessionName
                    $existingRecord.SessionId = $session.SessionId
                    $existingRecord.IdleTime = $session.IdleTime
                }
                else {
                    # Add new historical record
                    $global:QUserCache.HistoricalData.ComputerSessions[$computerKey] += $historicalSession
                }

                # Update user sessions mapping
                if (-not $global:QUserCache.HistoricalData.UserSessions.ContainsKey($userKey)) {
                    $global:QUserCache.HistoricalData.UserSessions[$userKey] = @()
                }

                # Check if we have a recent user session record
                $existingUserRecord = $global:QUserCache.HistoricalData.UserSessions[$userKey] |
                    Where-Object {
                        $_.ComputerName.ToUpperInvariant() -eq $computerKey -and
                        ($lastSeen = Get-SafeDateTime -Value $_.LastSeen) -ne $null -and
                        ($now - $lastSeen).TotalHours -lt 24
                    } |
                    Select-Object -First 1
                if ($existingUserRecord) {
                    $existingUserRecord.LastSeen = $now
                    $existingUserRecord.SeenCount++
                }
                else {
                    $global:QUserCache.HistoricalData.UserSessions[$userKey] += [PSCustomObject]@{
                        ComputerName = $ComputerName
                        FirstSeen    = $now
                        LastSeen     = $now
                        SeenCount    = 1
                    }
                }
            }
            finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }
        }
    }

    # Cleanup and save historical data only if enabled
    if ($historicalEnabled) {
        # Cleanup old records periodically (once per day)
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            if (($now - $global:QUserCache.HistoricalData.LastCleanup).TotalDays -gt 1) {
                # Update marker under lock, do cleanup outside to limit lock duration
                $global:QUserCache.HistoricalData.LastCleanup = $now
                $doCleanup = $true
            }
            else { $doCleanup = $false }
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }
        if ($doCleanup) { Cleanup-QUserHistoricalData }

        # Save historical data periodically
        Save-QUserHistoricalData
    }
}

function Cleanup-QUserHistoricalData {
    <#
    .SYNOPSIS
        Removes historical session records older than a specified number of days.
    .DESCRIPTION
        Iterates through the computer-session and user-session historical data
        structures under a thread-safe lock and removes any records whose
        LastSeen timestamp is older than MaxDaysToKeep days ago.
    .PARAMETER MaxDaysToKeep
        Number of days of history to retain.  Records older than this are
        removed.  Defaults to 30.
    .OUTPUTS
        None.  The function modifies $global:QUserCache.HistoricalData in place.
    .EXAMPLE
        Cleanup-QUserHistoricalData
        Removes historical records older than 30 days.
    .EXAMPLE
        Cleanup-QUserHistoricalData -MaxDaysToKeep 7
        Removes historical records older than 7 days.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxDaysToKeep = 30
    )

    if (-not $global:QUserCache.HistoricalData) { return }

    # Helper to safely get DateTime from potentially corrupted data
    function Get-SafeDateTime {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [DateTime]) { return $Value }
        if ($Value -is [Array] -and $Value.Count -gt 0) {
            $first = $Value[0]
            if ($first -is [DateTime]) { return $first }
            if ($first -is [String]) {
                $parsed = $null
                if ([DateTime]::TryParse($first, [ref]$parsed)) { return $parsed }
            }
        }
        if ($Value -is [String]) {
            $parsed = $null
            if ([DateTime]::TryParse($Value, [ref]$parsed)) { return $parsed }
        }
        return $null
    }

    $cutoffDate = (Get-Date).AddDays(-$MaxDaysToKeep)

    try {
        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
        # Clean computer sessions
        foreach ($computerKey in $global:QUserCache.HistoricalData.ComputerSessions.Keys) {
            $sessions = $global:QUserCache.HistoricalData.ComputerSessions[$computerKey]
            $global:QUserCache.HistoricalData.ComputerSessions[$computerKey] = $sessions |
                Where-Object {
                    $lastSeen = Get-SafeDateTime -Value $_.LastSeen
                    $null -ne $lastSeen -and $lastSeen -gt $cutoffDate
                }
        }

        # Clean user sessions
        foreach ($userKey in $global:QUserCache.HistoricalData.UserSessions.Keys) {
            $sessions = $global:QUserCache.HistoricalData.UserSessions[$userKey]
            $global:QUserCache.HistoricalData.UserSessions[$userKey] = $sessions |
                Where-Object {
                    $lastSeen = Get-SafeDateTime -Value $_.LastSeen
                    $null -ne $lastSeen -and $lastSeen -gt $cutoffDate
                }
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "QUser historical data cleanup completed" -Level "Verbose"
    }
}

function Save-QUserHistoricalData {
    <#
    .SYNOPSIS
        Persists the in-memory historical session data to an XML file on disk.
    .DESCRIPTION
        Snapshots the current historical data under a thread-safe lock and
        exports it to a CliXml file in the application data directory.  The
        data path is read from $global:AppConfig.DataPath or falls back to
        %ProgramData%\ADapp\Data.
    .OUTPUTS
        None.  A file is written to disk.
    .EXAMPLE
        Save-QUserHistoricalData
        Writes the current historical session data to quser_history.xml.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not $global:QUserCache.HistoricalData) { return }

        $dataPath = $null
        if ($global:AppConfig -and $global:AppConfig.DataPath) {
            $dataPath = $global:AppConfig.DataPath
        }
        else {
            $dataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        }

        if (-not (Test-Path $dataPath)) {
            New-Item -Path $dataPath -ItemType Directory -Force | Out-Null
        }

        $historicalFile = Join-Path -Path $dataPath -ChildPath "quser_history.xml"

        # Snapshot data under lock to avoid concurrent modification during export
        $toSave = $null
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            $toSave = $global:QUserCache.HistoricalData
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        if ($toSave -and ($toSave.ComputerSessions.Count -gt 0 -or $toSave.UserSessions.Count -gt 0)) {
            Export-Clixml -Path $historicalFile -InputObject $toSave -Force
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error saving QUser historical data: $_" -Level "Warning"
        }
    }
}

function Load-QUserHistoricalData {
    <#
    .SYNOPSIS
        Loads persisted historical session data from disk into the in-memory cache.
    .DESCRIPTION
        Imports a previously saved CliXml file containing historical session data,
        normalises any corrupted DateTime values (arrays or strings), rebuilds the
        UserSessions index from ComputerSessions if needed, and stores the result
        into $global:QUserCache.HistoricalData under a thread-safe lock.
    .OUTPUTS
        None.  The function modifies $global:QUserCache.HistoricalData in place.
    .EXAMPLE
        Load-QUserHistoricalData
        Loads historical data from the default quser_history.xml file.
    #>
    [CmdletBinding()]
    param()

    try {
        # Helper function to normalize DateTime values that might be arrays or strings
        function Normalize-DateTime {
            param([object]$Value)

            if ($null -eq $Value) { return $null }

            # If it's already a DateTime, return it
            if ($Value -is [DateTime]) { return $Value }

            # If it's an array, take the first element and recurse
            if ($Value -is [Array] -and $Value.Count -gt 0) {
                return Normalize-DateTime -Value $Value[0]
            }

            # If it's a string, try to parse it
            if ($Value -is [String] -and -not [string]::IsNullOrWhiteSpace($Value)) {
                $parsed = $null
                if ([DateTime]::TryParse($Value, [ref]$parsed)) {
                    return $parsed
                }
            }

            # If we can't convert it, return null
            return $null
        }

        $dataPath = $null
        if ($global:AppConfig -and $global:AppConfig.DataPath) {
            $dataPath = $global:AppConfig.DataPath
        }
        else {
            $dataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        }

        $historicalFile = Join-Path -Path $dataPath -ChildPath "quser_history.xml"

        if (Test-Path $historicalFile) {
            $loadedData = Import-Clixml -Path $historicalFile
            if ($loadedData) {
                try {
                    [System.Threading.Monitor]::Enter($script:QUserCacheLock)
                    $global:QUserCache.HistoricalData = $loadedData

                    # Rebuild UserSessions index from ComputerSessions if it's missing or incomplete
                    if (-not $loadedData.UserSessions) {
                        $loadedData.UserSessions = @{}
                    }

                    # Rebuild the UserSessions mapping from ComputerSessions data
                    foreach ($computerKey in $loadedData.ComputerSessions.Keys) {
                        foreach ($session in $loadedData.ComputerSessions[$computerKey]) {
                            if ($session -and -not [string]::IsNullOrWhiteSpace($session.Username)) {
                                # Normalize DateTime properties to handle arrays or corrupted data
                                $normalizedFirstSeen = Normalize-DateTime -Value $session.FirstSeen
                                $normalizedLastSeen = Normalize-DateTime -Value $session.LastSeen

                                # Skip this session if we can't normalize the dates
                                if ($null -eq $normalizedFirstSeen -or $null -eq $normalizedLastSeen) {
                                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                                        Write-Log -Message "Skipping session for $($session.Username) on $computerKey - invalid date values" -Level "Verbose"
                                    }
                                    continue
                                }

                                # Update the session object with normalized dates
                                $session.FirstSeen = $normalizedFirstSeen
                                $session.LastSeen = $normalizedLastSeen

                                $userKey = $session.Username.ToUpperInvariant()

                                if (-not $loadedData.UserSessions.ContainsKey($userKey)) {
                                    $loadedData.UserSessions[$userKey] = @()
                                }

                                # Check if we already have this computer in the user's list
                                $existingUserSession = $loadedData.UserSessions[$userKey] |
                                    Where-Object { $_.ComputerName.ToUpperInvariant() -eq $computerKey }

                                if (-not $existingUserSession) {
                                    # Add new user session record
                                    $loadedData.UserSessions[$userKey] += [PSCustomObject]@{
                                        ComputerName = $session.ComputerName
                                        FirstSeen    = $normalizedFirstSeen
                                        LastSeen     = $normalizedLastSeen
                                        SeenCount    = $session.SeenCount
                                    }
                                }
                                else {
                                    # Normalize existing session dates too
                                    $existingFirstSeen = Normalize-DateTime -Value $existingUserSession.FirstSeen
                                    $existingLastSeen = Normalize-DateTime -Value $existingUserSession.LastSeen

                                    if ($null -ne $existingFirstSeen) {
                                        $existingUserSession.FirstSeen = $existingFirstSeen
                                    }
                                    if ($null -ne $existingLastSeen) {
                                        $existingUserSession.LastSeen = $existingLastSeen
                                    }

                                    # Update existing record if this session is more recent
                                    if ($normalizedLastSeen -gt $existingLastSeen) {
                                        $existingUserSession.LastSeen = $normalizedLastSeen
                                        $existingUserSession.SeenCount = $session.SeenCount
                                    }
                                    if ($normalizedFirstSeen -lt $existingFirstSeen) {
                                        $existingUserSession.FirstSeen = $normalizedFirstSeen
                                    }
                                }
                            }
                        }
                    }

                    # Also normalize dates in UserSessions that were already there
                    foreach ($userKey in $loadedData.UserSessions.Keys) {
                        foreach ($userSession in $loadedData.UserSessions[$userKey]) {
                            if ($userSession) {
                                $normalizedFirst = Normalize-DateTime -Value $userSession.FirstSeen
                                $normalizedLast = Normalize-DateTime -Value $userSession.LastSeen
                                if ($null -ne $normalizedFirst) {
                                    $userSession.FirstSeen = $normalizedFirst
                                }
                                if ($null -ne $normalizedLast) {
                                    $userSession.LastSeen = $normalizedLast
                                }
                            }
                        }
                    }
                }
                finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    $totalSessions = ($loadedData.ComputerSessions.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
                    $totalUsers = if ($loadedData.UserSessions) { $loadedData.UserSessions.Keys.Count } else { 0 }
                    Write-Log -Message "Loaded QUser historical data: $totalSessions session records, $totalUsers users" -Level "Info"
                }
            }
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error loading QUser historical data: $_" -Level "Warning"
        }
    }
}

function Get-QUserHistoricalSessions {
    <#
    .SYNOPSIS
        Retrieves historical session records filtered by computer, user, or both.
    .DESCRIPTION
        Queries the in-memory historical data structures for session records
        within the specified number of days.  Results can be filtered by
        ComputerName, Username, or both.  Returns records sorted by LastSeen
        in descending order.
    .PARAMETER ComputerName
        Optional hostname to filter results to a single computer.
    .PARAMETER Username
        Optional username to filter results to a single user.
    .PARAMETER DaysBack
        Number of days of history to search.  Defaults to 30.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of historical session records sorted by LastSeen descending.
    .EXAMPLE
        Get-QUserHistoricalSessions -ComputerName 'SERVER01' -DaysBack 7
        Returns sessions recorded on SERVER01 within the last 7 days.
    .EXAMPLE
        Get-QUserHistoricalSessions -Username 'jsmith'
        Returns all historical sessions for user jsmith within the last 30 days.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,

        [string]$Username,

        [int]$DaysBack = 30
    )

    if (-not $global:QUserCache.HistoricalData) { return @() }

    # Helper to safely get DateTime from potentially corrupted data
    function Get-SafeDateTime {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [DateTime]) { return $Value }
        if ($Value -is [Array] -and $Value.Count -gt 0) {
            $first = $Value[0]
            if ($first -is [DateTime]) { return $first }
            if ($first -is [String]) {
                $parsed = $null
                if ([DateTime]::TryParse($first, [ref]$parsed)) { return $parsed }
            }
        }
        if ($Value -is [String]) {
            $parsed = $null
            if ([DateTime]::TryParse($Value, [ref]$parsed)) { return $parsed }
        }
        return $null
    }

    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $results = @()

    try {
        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
        if ($ComputerName) {
            $computerKey = $ComputerName.ToUpperInvariant()
            if ($global:QUserCache.HistoricalData.ComputerSessions.ContainsKey($computerKey)) {
                $sessions = $global:QUserCache.HistoricalData.ComputerSessions[$computerKey] |
                    Where-Object {
                        $lastSeen = Get-SafeDateTime -Value $_.LastSeen
                        $null -ne $lastSeen -and $lastSeen -gt $cutoffDate
                    }

                if ($Username) {
                    $userKey = $Username.ToUpperInvariant()
                    $sessions = $sessions | Where-Object { $_.Username.ToUpperInvariant() -eq $userKey }
                }

                $results = $sessions
            }
        }
        elseif ($Username) {
            $userKey = $Username.ToUpperInvariant()
            if ($global:QUserCache.HistoricalData.UserSessions.ContainsKey($userKey)) {
                $userSessions = $global:QUserCache.HistoricalData.UserSessions[$userKey] |
                    Where-Object {
                        $lastSeen = Get-SafeDateTime -Value $_.LastSeen
                        $null -ne $lastSeen -and $lastSeen -gt $cutoffDate
                    }
                $results = $userSessions
            }
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

    return $results | Sort-Object LastSeen -Descending
}

function Parse-QUserOutput {
    <#
    .SYNOPSIS
        Parses raw quser.exe text output into structured session objects.
    .DESCRIPTION
        Takes the line-by-line string output from quser.exe, skips the header
        row, and splits each remaining line into its constituent fields
        (Username, SessionName, SessionId, State, IdleTime, LogonTime).
        Each parsed line is returned as a PSCustomObject.
    .PARAMETER QUserOutput
        An array of strings representing the raw output lines from quser.exe.
    .PARAMETER ComputerName
        The hostname that produced the quser output, attached to each result
        object for correlation.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of parsed session objects with properties: ComputerName,
        Username, SessionName, SessionId, State, IdleTime, LogonTime, Source,
        and Timestamp.
    .EXAMPLE
        Parse-QUserOutput -QUserOutput $lines -ComputerName 'SERVER01'
        Parses the supplied quser output and tags each session with SERVER01.
    #>
    [CmdletBinding()]
    param(
        [string[]]$QUserOutput,

        [string]$ComputerName
    )

    $sessions = @()

    if (-not $QUserOutput -or $QUserOutput.Count -lt 2) {
        return $sessions
    }

    try {
        # Skip the header line and process each session line
        for ($i = 1; $i -lt $QUserOutput.Count; $i++) {
            $line = $QUserOutput[$i]
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # Parse quser output format
            # USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
            # >administrator         console             1  Active      none   1/15/2024 2:30 PM

            # Handle the case where username might be prefixed with ">" (often preceded by spaces)
            $cleanLine = $line -replace '^\s*>', ''

            # Split by multiple spaces to handle variable spacing
            $parts = $cleanLine -split '\s{2,}' | Where-Object { $_ -notmatch '^\s*$' }

            if ($parts.Count -ge 4) {
                $username    = $parts[0].Trim()
                $sessionName = $parts[1].Trim()
                $sessionId   = $parts[2].Trim()
                $state       = $parts[3].Trim()
                $idleTime    = if ($parts.Count -gt 4) { $parts[4].Trim() } else { "" }
                $logonTime   = if ($parts.Count -gt 5) { $parts[5].Trim() } else { "" }

                # Create session object
                $session = [PSCustomObject]@{
                    ComputerName = $ComputerName
                    Username     = $username
                    SessionName  = $sessionName
                    SessionId    = $sessionId
                    State        = $state
                    IdleTime     = $idleTime
                    LogonTime    = $logonTime
                    Source       = "QUser"
                    Timestamp    = Get-Date
                }

                $sessions += $session
            }
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error parsing quser output for ${ComputerName}: $_" -Level "Warning"
        }
    }

    return $sessions
}

function Update-QUserCache {
    <#
    .SYNOPSIS
        Refreshes the QUser session cache for a list of computers.
    .DESCRIPTION
        Queries quser session data for the supplied (or auto-discovered) list of
        computers and stores the results in the global QUser cache.  Supports
        both serial and parallel (background job) processing, controlled by the
        Performance.MaxConcurrentJobs setting.  Historical tracking is updated
        for each computer that returns results.
    .PARAMETER ComputerNames
        An array of computer hostnames to query.  If omitted, the function
        discovers computers via Get-OnlineComputers.
    .PARAMETER Force
        When specified, reinitialises the cache before querying.
    .PARAMETER TimeoutSeconds
        Per-computer quser timeout in seconds.  Defaults to 5.
    .PARAMETER MaxComputers
        Maximum number of computers to query in a single refresh cycle.
        Defaults to 50.
    .OUTPUTS
        System.Boolean
        Returns $true on success, $false on failure.
    .EXAMPLE
        Update-QUserCache -ComputerNames @('PC01','PC02') -TimeoutSeconds 3
        Queries PC01 and PC02 with a 3-second timeout and caches the results.
    .EXAMPLE
        Update-QUserCache -Force
        Reinitialises the cache and discovers computers automatically.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerNames,

        [switch]$Force,

        [int]$TimeoutSeconds = 5,

        [int]$MaxComputers = 50
    )

    try {
        # Initialize cache if it doesn't exist
        if (-not $global:QUserCache -or $Force) {
            Initialize-QUserCache
        }

        # If no computer names provided, get them from AD or PDQ
        if (-not $ComputerNames -or $ComputerNames.Count -eq 0) {
            $ComputerNames = Get-OnlineComputers -MaxCount $MaxComputers
        }

        if (-not $ComputerNames -or $ComputerNames.Count -eq 0) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "No computers found for QUser query" -Level "Warning"
            }
            return $false
        }

        # Limit the number of computers to avoid overwhelming the system
        if ($ComputerNames.Count -gt $MaxComputers) {
            $ComputerNames = $ComputerNames[0..($MaxComputers - 1)]
        }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Starting QUser cache update for $($ComputerNames.Count) computers" -Level "Info"
        }

        # Clear existing cache data (thread-safe)
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            $global:QUserCache.Data.Clear()
            $global:QUserCache.UserToComputers.Clear()
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        $successCount = 0
        $totalSessions = 0

        # Determine parallelism from settings
        $maxParallel = 1
        try {
            if ($global:Settings -and $global:Settings.Performance -and $global:Settings.Performance.MaxConcurrentJobs) {
                $maxParallel = [Math]::Max(1, [int]$global:Settings.Performance.MaxConcurrentJobs)
            }
            else { $maxParallel = 5 }
        } catch { $maxParallel = 5 }

        if ($maxParallel -le 1 -or $ComputerNames.Count -le 1) {
            # Serial processing
            foreach ($computer in $ComputerNames) {
                try {
                    $opStart = Get-Date
                    $sessions = Get-QUserInfo -ComputerName $computer -TimeoutSeconds $TimeoutSeconds

                    if ($sessions.Count -gt 0) {
                        $computerKey = $computer.ToUpperInvariant()
                        try {
                            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
                            $global:QUserCache.Data[$computerKey] = @{
                                Sessions  = $sessions
                                Timestamp = Get-Date
                            }
                        }
                        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }
                        $totalSessions += $sessions.Count
                        Update-QUserHistoricalData -ComputerName $computer -Sessions $sessions
                        $successCount++
                    }
                    $dur = [int]((Get-Date) - $opStart).TotalMilliseconds
                    try { Write-LogEvent -Operation 'QUserQuery' -EventId 3001 -Context @{ computer = $computer; sessions = $sessions.Count } -DurationMs $dur } catch {}
                }
                catch {
                    continue
                }
            }
        }
        else {
            # Parallel processing with throttling
            $jobs = New-Object System.Collections.ArrayList
            $modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'QUserQuery.psm1'

            foreach ($computer in $ComputerNames) {
                # Throttle: wait for a slot to free up before starting the next job
                while ($jobs.Count -ge $maxParallel) {
                    $finished = Wait-Job -Job $jobs -Any -Timeout 5
                    if ($finished) {
                        foreach ($j in ($jobs | Where-Object { $_.HasMoreData -or $_.State -in 'Completed', 'Failed', 'Stopped' })) {
                            try {
                                $result = Receive-Job -Job $j -ErrorAction SilentlyContinue
                                if ($result -and $result.Sessions) {
                                    $compKey = ($result.Computer).ToUpperInvariant()
                                    try {
                                        [System.Threading.Monitor]::Enter($script:QUserCacheLock)
                                        $global:QUserCache.Data[$compKey] = @{
                                            Sessions  = $result.Sessions
                                            Timestamp = Get-Date
                                        }
                                    }
                                    finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }
                                    $totalSessions += $result.Sessions.Count
                                    Update-QUserHistoricalData -ComputerName $result.Computer -Sessions $result.Sessions
                                    if ($result.Sessions.Count -gt 0) { $successCount++ }
                                }
                            } catch {}
                            Remove-Job -Job $j -Force -ErrorAction SilentlyContinue | Out-Null
                            [void]$jobs.Remove($j)
                        }
                    }
                    else { break }
                }

                # Start new job
                $job = Start-Job -ScriptBlock {
                    param($comp, $modulePathArg, $timeout)
                    try { Import-Module $modulePathArg -Force -DisableNameChecking | Out-Null } catch {}
                    $start = Get-Date
                    try {
                        $sessionsLocal = Get-QUserInfo -ComputerName $comp -TimeoutSeconds $timeout
                    } catch { $sessionsLocal = @() }
                    $d = [int]((Get-Date) - $start).TotalMilliseconds
                    return [PSCustomObject]@{ Computer = $comp; Sessions = $sessionsLocal; DurationMs = $d }
                } -ArgumentList $computer, $modulePath, $TimeoutSeconds

                [void]$jobs.Add($job)
            }

            # Drain remaining jobs
            while ($jobs.Count -gt 0) {
                $finished = Wait-Job -Job $jobs -Any -Timeout 10
                foreach ($j in ($jobs | Where-Object { $_.HasMoreData -or $_.State -in 'Completed', 'Failed', 'Stopped' })) {
                    try {
                        $result = Receive-Job -Job $j -ErrorAction SilentlyContinue
                        if ($result -and $result.Sessions) {
                            $compKey = ($result.Computer).ToUpperInvariant()
                            try {
                                [System.Threading.Monitor]::Enter($script:QUserCacheLock)
                                $global:QUserCache.Data[$compKey] = @{
                                    Sessions  = $result.Sessions
                                    Timestamp = Get-Date
                                }
                            }
                            finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }
                            $totalSessions += $result.Sessions.Count
                            Update-QUserHistoricalData -ComputerName $result.Computer -Sessions $result.Sessions
                            if ($result.Sessions.Count -gt 0) { $successCount++ }
                            try { Write-LogEvent -Operation 'QUserQuery' -EventId 3001 -Context @{ computer = $result.Computer; sessions = $result.Sessions.Count } -DurationMs $result.DurationMs } catch {}
                        }
                    } catch {}
                    Remove-Job -Job $j -Force -ErrorAction SilentlyContinue | Out-Null
                    [void]$jobs.Remove($j)
                }
            }
        }

        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            $global:QUserCache.LastUpdated = Get-Date
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "QUser cache updated: $successCount/$($ComputerNames.Count) computers successful, $totalSessions active sessions found" -Level "Info"
        }
        return $true
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error updating QUser cache: $_" -Level "Error"
        }
        return $false
    }
}

function Get-OnlineComputers {
    <#
    .SYNOPSIS
        Returns a list of computer names to query for user sessions.
    .DESCRIPTION
        Attempts to retrieve computer names from the PDQ Inventory cache first.
        If no PDQ data is available, falls back to an Active Directory query for
        enabled computer accounts.  If that also fails, returns the local host
        as a last-resort fallback.
    .PARAMETER MaxCount
        Maximum number of computer names to return.  Defaults to 50.
    .OUTPUTS
        System.String[]
        An array of computer hostnames.
    .EXAMPLE
        Get-OnlineComputers -MaxCount 10
        Returns up to 10 computer names from the best available source.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxCount = 50
    )

    $computers = @()

    try {
        # Try to get from PDQ cache first
        if ($global:PDQInventoryCache -and $global:PDQInventoryCache.Data) {
            $computers = $global:PDQInventoryCache.Data.Keys | Select-Object -First $MaxCount
        }

        # If no PDQ data, get from AD
        if ($computers.Count -eq 0) {
            try {
                $adComputers = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties Name -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name -First $MaxCount
                $computers = $adComputers
            }
            catch {
                # Fallback to local machine when AD is unreachable
                $computers = @("localhost", $env:COMPUTERNAME)
            }
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Error getting computer list: $_" -Level "Warning"
        }
        # Fallback to local computer
        $computers = @("localhost", $env:COMPUTERNAME)
    }

    return $computers
}

function Get-QUserSessionsForComputer {
    <#
    .SYNOPSIS
        Returns cached or fresh user sessions for a single computer.
    .DESCRIPTION
        Convenience wrapper around Get-QUserInfoWithCache that reads the cache
        TTL from settings and returns all active sessions for the specified
        computer.
    .PARAMETER ComputerName
        The hostname or FQDN of the computer to retrieve sessions for.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of session objects, or an empty array on failure.
    .EXAMPLE
        Get-QUserSessionsForComputer -ComputerName 'PC042'
        Returns active user sessions on PC042 using the configured cache TTL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Determine cache TTL from settings if available
        $ttl = 5
        try {
            if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.CacheAgeMinutes) {
                $ttl = [int]$global:Settings.QUser.CacheAgeMinutes
            }
        } catch { $ttl = 5 }

        # Use the cached version for better performance
        $sessions = Get-QUserInfoWithCache -ComputerName $ComputerName -CacheAgeMinutes $ttl
        return $sessions
    }
    catch {
        return @()
    }
}

function Get-QUserComputersForUser {
    <#
    .SYNOPSIS
        Returns the list of computers where a user is known to be logged in.
    .DESCRIPTION
        Looks up the user-to-computers mapping in the global QUser cache
        (thread-safe) and returns all computer names currently associated with
        the specified username.
    .PARAMETER Username
        The username (sAMAccountName) to look up.
    .OUTPUTS
        System.String[]
        An array of computer hostnames, or an empty array if none are found.
    .EXAMPLE
        Get-QUserComputersForUser -Username 'jsmith'
        Returns all computers where jsmith currently has a session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        if (-not $global:QUserCache) { return @() }

        $key = $Username.ToUpperInvariant()
        try {
            [System.Threading.Monitor]::Enter($script:QUserCacheLock)
            if ($global:QUserCache.UserToComputers.ContainsKey($key)) {
                return $global:QUserCache.UserToComputers[$key]
            }
        }
        finally { [System.Threading.Monitor]::Exit($script:QUserCacheLock) }

        return @()
    }
    catch {
        return @()
    }
}

function Get-CombinedUserLocationData {
    <#
    .SYNOPSIS
        Aggregates user location data from live QUser, historical, and PDQ sources.
    .DESCRIPTION
        Queries multiple data sources to build a unified view of where a user is
        (or has recently been) logged in.  Live QUser sessions are listed first,
        followed by historical sessions from the last 7 days, and finally PDQ
        Inventory data for any computers not already covered.  Duplicate
        computers are suppressed across source tiers.
    .PARAMETER Username
        The username (sAMAccountName) to locate.
    .PARAMETER IncludeQUser
        Include live QUser session data.  Defaults to $true.
    .PARAMETER IncludePDQ
        Include PDQ Inventory data.  Defaults to $true.
    .PARAMETER IncludeHistorical
        Include historical QUser session data.  Defaults to $true.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of location result objects with Computer, Source, Status,
        LastSeen, and optionally SessionDetails properties.
    .EXAMPLE
        Get-CombinedUserLocationData -Username 'jsmith'
        Returns all known locations for jsmith from every available source.
    .EXAMPLE
        Get-CombinedUserLocationData -Username 'jsmith' -IncludePDQ:$false
        Returns location data for jsmith excluding PDQ Inventory results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [switch]$IncludeQUser = $true,

        [switch]$IncludePDQ = $true,

        [switch]$IncludeHistorical = $true
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Get-CombinedUserLocationData: Called for $Username (QUser=$IncludeQUser, PDQ=$IncludePDQ, Historical=$IncludeHistorical)" -Level "Info"
    }

    $results = @()
    $pdqComputers = @()
    $liveSessionComputers = @()
    $historicalComputers = @()

    # Get PDQ data first (for use as candidates, but will add to results last)
    if ($IncludePDQ) {
        try {
            if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                $pdqComputers = Get-PDQComputersForUser -Username $Username
                $pdqCount = if ($pdqComputers) { $pdqComputers.Count } else { 0 }
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Get-CombinedUserLocationData: Found $pdqCount PDQ computers for $Username" -Level "Info"
                }
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting PDQ data for user $Username`: $_" -Level "Warning"
            }
        }
    }

    # Get current QUser data -- add to results first for priority display
    if ($IncludeQUser) {
        try {
            # First check cache for computers with this user
            $qUserComputers = Get-QUserComputersForUser -Username $Username
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Get-CombinedUserLocationData: Found $($qUserComputers.Count) cached QUser computers for $Username" -Level "Verbose"
            }

            # Build candidate computers to probe for fresh live data without constant scanning
            $candidateSet = New-Object 'System.Collections.Generic.HashSet[string]'
            $norm = { param($n) if ([string]::IsNullOrWhiteSpace($n)) { $null } else { $n.ToUpperInvariant() } }

            # Include PDQ computers
            if ($pdqComputers -and $pdqComputers.Count -gt 0) {
                foreach ($c in $pdqComputers) { $key = & $norm $c; if ($key) { [void]$candidateSet.Add($key) } }
            }

            # Include known QUser mapping computers
            if ($qUserComputers -and $qUserComputers.Count -gt 0) {
                foreach ($c in $qUserComputers) { $key = & $norm $c; if ($key) { [void]$candidateSet.Add($key) } }
            }

            # Include most-recent historical computers for this user
            try {
                $daysBack = 7
                $hist = Get-QUserHistoricalSessions -Username $Username -DaysBack $daysBack
                if ($hist) {
                    # Sort by LastSeen desc and take a limited number
                    $maxProbe = 5
                    try {
                        if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.MaxComputersPerQuery) {
                            $maxProbe = [Math]::Max(1, [int]$global:Settings.QUser.MaxComputersPerQuery)
                        }
                    } catch { $maxProbe = 5 }

                    $histComputers = ($hist | Sort-Object LastSeen -Descending | Select-Object -ExpandProperty ComputerName -Unique | Select-Object -First $maxProbe)
                    foreach ($c in $histComputers) { $key = & $norm $c; if ($key) { [void]$candidateSet.Add($key) } }
                }
            } catch {}

            # Probe candidates using cached quser with TTL to refresh mapping if needed
            foreach ($key in $candidateSet) {
                $comp = $key
                try {
                    $sessions = Get-QUserSessionsForComputer -ComputerName $comp
                    $userSessions = $sessions | Where-Object { $_.Username.ToUpperInvariant() -eq $Username.ToUpperInvariant() }
                    if ($userSessions -and $userSessions.Count -gt 0) {
                        if ($qUserComputers -notcontains $comp) { $qUserComputers += $comp }
                    }
                } catch { continue }
            }

            # Now process all computers found (from cache and fresh queries) -- add to results first
            foreach ($computer in $qUserComputers) {
                $sessions = Get-QUserSessionsForComputer -ComputerName $computer
                $userSessions = $sessions | Where-Object { $_.Username.ToUpperInvariant() -eq $Username.ToUpperInvariant() }

                foreach ($session in $userSessions) {
                    $liveSessionComputers += $computer

                    $results += [PSCustomObject]@{
                        Computer       = $computer
                        Source         = "Live Session (QUser)"
                        Status         = $session.State
                        LastSeen       = $session.Timestamp.ToString("g")
                        SessionDetails = "$($session.SessionName) (ID: $($session.SessionId))"
                    }
                }
            }
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Get-CombinedUserLocationData: Added $($liveSessionComputers.Count) live QUser sessions for $Username" -Level "Verbose"
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting QUser data for user $Username`: $_" -Level "Warning"
            }
        }
    }

    # Get historical QUser data -- add second
    if ($IncludeHistorical) {
        try {
            $historicalSessions = @(Get-QUserHistoricalSessions -Username $Username -DaysBack 7)
            $histCount = $historicalSessions.Count
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Get-CombinedUserLocationData: Found $histCount historical sessions for $Username" -Level "Info"
            }
            foreach ($session in $historicalSessions) {
                # Skip if we already have a live session for this computer
                $hasLiveSession = $liveSessionComputers -contains $session.ComputerName
                if ($hasLiveSession) { continue }

                $historicalComputers += $session.ComputerName

                $results += [PSCustomObject]@{
                    Computer       = $session.ComputerName
                    Source         = "Recent Sessions (Last 7 Days)"
                    Status         = "Historical"
                    LastSeen       = $session.LastSeen.ToString("g")
                    SessionDetails = "Seen $($session.SeenCount) times"
                }
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting historical QUser data for user $Username`: $_" -Level "Warning"
            }
        }
    }

    # Add PDQ data last -- only for computers not already shown
    $pdqAdded = 0
    if ($IncludePDQ -and $pdqComputers -and $pdqComputers.Count -gt 0) {
        foreach ($computer in $pdqComputers) {
            if (-not [string]::IsNullOrWhiteSpace($computer)) {
                # Skip if we already have live or historical session for this computer
                if (($liveSessionComputers -contains $computer) -or ($historicalComputers -contains $computer)) {
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log -Message "Get-CombinedUserLocationData: Skipping PDQ computer $computer for $Username (already have QUser/historical data)" -Level "Verbose"
                    }
                    continue
                }

                $results += [PSCustomObject]@{
                    Computer = $computer
                    Source   = "PDQ Inventory"
                    Status   = "Offline/Cached"
                    LastSeen = "Unknown"
                }
                $pdqAdded++
            }
        }
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Get-CombinedUserLocationData: Added $pdqAdded PDQ computers for $Username (had $($pdqComputers.Count) total)" -Level "Verbose"
        }
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Get-CombinedUserLocationData: Returning $($results.Count) total results for $Username" -Level "Verbose"
    }
    return $results
}

function Get-CombinedComputerUserData {
    <#
    .SYNOPSIS
        Aggregates user data for a single computer from live, historical, and PDQ sources.
    .DESCRIPTION
        Queries multiple data sources to build a unified view of which users are
        (or have recently been) logged into a given computer.  Live QUser
        sessions are listed first, followed by historical sessions from the
        last 7 days, and finally PDQ Inventory data for any users not already
        covered.  Duplicate users are suppressed across source tiers.
    .PARAMETER ComputerName
        The hostname or FQDN of the computer to query.
    .PARAMETER IncludeQUser
        Include live QUser session data.  Defaults to $true.
    .PARAMETER IncludePDQ
        Include PDQ Inventory data.  Defaults to $true.
    .PARAMETER IncludeHistorical
        Include historical QUser session data.  Defaults to $true.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        An array of user result objects with Username, Source, Status,
        LastSeen, and optionally SessionDetails / IdleTime / LogonTime
        properties.
    .EXAMPLE
        Get-CombinedComputerUserData -ComputerName 'SERVER01'
        Returns all known users for SERVER01 from every available source.
    .EXAMPLE
        Get-CombinedComputerUserData -ComputerName 'PC042' -IncludeHistorical:$false
        Returns user data for PC042 excluding historical session records.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [switch]$IncludeQUser = $true,

        [switch]$IncludePDQ = $true,

        [switch]$IncludeHistorical = $true
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Get-CombinedComputerUserData: Called for $ComputerName (QUser=$IncludeQUser, PDQ=$IncludePDQ, Historical=$IncludeHistorical)" -Level "Info"
    }

    $results = @()

    # Get current QUser data first -- live session data has priority
    if ($IncludeQUser) {
        try {
            $sessions = Get-QUserSessionsForComputer -ComputerName $ComputerName
            $sessionCount = @($sessions).Count
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Get-CombinedComputerUserData: Found $sessionCount QUser sessions for $ComputerName" -Level "Info"
            }
            foreach ($session in $sessions) {
                $results += [PSCustomObject]@{
                    Username       = $session.Username
                    Source         = "Live Session (QUser)"
                    Status         = $session.State
                    LastSeen       = $session.Timestamp.ToString("g")
                    SessionDetails = "$($session.SessionName) (ID: $($session.SessionId))"
                    IdleTime       = $session.IdleTime
                    LogonTime      = $session.LogonTime
                }
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting QUser data for computer $ComputerName`: $_" -Level "Warning"
            }
        }
    }

    # Get historical QUser data
    if ($IncludeHistorical) {
        try {
            $historicalSessions = Get-QUserHistoricalSessions -ComputerName $ComputerName -DaysBack 7
            foreach ($session in $historicalSessions) {
                # Skip if we already have a live session for this user
                $hasLiveSession = $results | Where-Object { $_.Username -eq $session.Username -and $_.Source -like "*Live Session*" }
                if ($hasLiveSession) { continue }

                $results += [PSCustomObject]@{
                    Username       = $session.Username
                    Source         = "Recent Sessions (Last 7 Days)"
                    Status         = "Historical"
                    LastSeen       = $session.LastSeen.ToString("g")
                    SessionDetails = "Seen $($session.SeenCount) times, First: $($session.FirstSeen.ToString('g'))"
                    IdleTime       = ""
                    LogonTime      = $session.LogonTime
                }
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting historical QUser data for computer $ComputerName`: $_" -Level "Warning"
            }
        }
    }

    # Get PDQ data last -- cached/offline data
    if ($IncludePDQ) {
        try {
            if (Get-Command Get-PDQUsersForComputer -ErrorAction SilentlyContinue) {
                $pdqUsers = Get-PDQUsersForComputer -ComputerName $ComputerName
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Message "Get-CombinedComputerUserData: Found $($pdqUsers.Count) PDQ users for $ComputerName" -Level "Verbose"
                }
                foreach ($user in $pdqUsers) {
                    if (-not [string]::IsNullOrWhiteSpace($user)) {
                        # Skip if we already have live or historical session for this user
                        $existingUser = $results | Where-Object { $_.Username -eq $user }
                        if ($existingUser) {
                            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                                Write-Log -Message "Get-CombinedComputerUserData: Skipping PDQ user $user (already have QUser/historical data)" -Level "Verbose"
                            }
                            continue
                        }

                        $results += [PSCustomObject]@{
                            Username = $user
                            Source   = "PDQ Inventory"
                            Status   = "Offline/Cached"
                            LastSeen = "Unknown"
                        }
                    }
                }
            }
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Message "Error getting PDQ data for computer $ComputerName`: $_" -Level "Warning"
            }
        }
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Get-CombinedComputerUserData: Returning $($results.Count) total results for $ComputerName" -Level "Verbose"
    }
    return $results
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-QUserInfo, Get-QUserInfoWithCache, Initialize-QUserCache, Update-QUserCache, Get-QUserSessionsForComputer, Get-QUserComputersForUser, Get-CombinedUserLocationData, Get-CombinedComputerUserData, Get-QUserHistoricalSessions
