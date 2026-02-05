#Requires -Version 5.1

<#
.SYNOPSIS
    PDQ Inventory integration module for ADapp.
.DESCRIPTION
    Provides functions to read PDQ Inventory CSV reports, maintain an in-memory
    cache of computer-to-user mappings, and optionally query the PDQ Inventory
    CLI (PDQInventory.exe) for real-time computer details.
.NOTES
    Module : PDQInventory
    Author : ADapp Team
#>

#region Functions

function Get-PDQSettings {
    <#
    .SYNOPSIS
        Retrieve PDQ Inventory report-based settings from the global configuration.
    .DESCRIPTION
        Returns a PSCustomObject containing the report folder path, file pattern,
        sort preference, and enabled flag.  Values fall back to sensible defaults
        when the global $Settings object is missing or incomplete.
    .OUTPUTS
        [PSCustomObject] with properties ReportFolder, ReportFilePattern,
        PreferLatestByModifiedTime, and Enabled.
    .EXAMPLE
        $cfg = Get-PDQSettings
        $cfg.ReportFolder
    #>
    [CmdletBinding()]
    param()

    $defaultFolder = $null
    try {
        if ($global:ScriptPath) {
            $defaultFolder = $global:ScriptPath
        }
        else {
            # App root is parent of Modules folder
            $defaultFolder = Split-Path -Parent $PSScriptRoot
        }
    }
    catch {
        $defaultFolder = Split-Path -Parent $PSScriptRoot
    }

    $defaults = [PSCustomObject]@{
        ReportFolder              = $defaultFolder
        ReportFilePattern         = "Logged in User.csv"
        Enabled                   = $true
    }

    try {
        $settingsObj = $null
        if ($global:Settings) { $settingsObj = $global:Settings }
        if ($settingsObj -and ($settingsObj.PSObject.Properties.Name -contains 'PDQ')) {
            $pdq = $settingsObj.PDQ
            return [PSCustomObject]@{
                ReportFolder              = $(if ([string]::IsNullOrWhiteSpace($pdq.ReportFolder)) { $defaults.ReportFolder } else { $pdq.ReportFolder })
                ReportFilePattern         = $(if ([string]::IsNullOrWhiteSpace($pdq.ReportFilePattern)) { $defaults.ReportFilePattern } else { $pdq.ReportFilePattern })
                Enabled                   = $(if ($null -eq $pdq.Enabled) { $defaults.Enabled } else { [bool]$pdq.Enabled })
            }
        }
    }
    catch {}

    return $defaults
}

function Get-PDQLatestReportPath {
    <#
    .SYNOPSIS
        Locate the most recently modified PDQ report file in a folder.
    .DESCRIPTION
        Searches ReportFolder for files matching FilePattern and returns the
        full path of the newest file by LastWriteTime.  If FilePattern is an
        exact file name that already exists, that path is returned immediately.
    .PARAMETER ReportFolder
        Directory to search for report files.
    .PARAMETER FilePattern
        Wildcard or exact file name to match.  Defaults to "*.csv".
    .OUTPUTS
        [string] Full path to the latest report, or $null if none found.
    .EXAMPLE
        Get-PDQLatestReportPath -ReportFolder 'C:\Reports' -FilePattern '*.csv'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFolder,

        [string]$FilePattern = "*.csv"
    )

    try {
        if ([string]::IsNullOrWhiteSpace($ReportFolder)) { return $null }
        if (-not (Test-Path -Path $ReportFolder)) { return $null }

        # If FilePattern is an exact file name and exists, return it
        $exactPath = Join-Path -Path $ReportFolder -ChildPath $FilePattern
        if (Test-Path -Path $exactPath) { return $exactPath }

        $files = Get-ChildItem -Path $ReportFolder -Filter $FilePattern -File -ErrorAction SilentlyContinue
        if (-not $files -or $files.Count -eq 0) { return $null }

        $latest = $files | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        return $latest.FullName
    }
    catch {
        try { Write-Log -Message "Get-PDQLatestReportPath error: $_" -Level "Warning" } catch {}
        return $null
    }
}

function Import-PDQReport {
    <#
    .SYNOPSIS
        Import a PDQ Inventory CSV report from disk.
    .DESCRIPTION
        Reads the CSV file at Path using Import-Csv and returns the resulting
        row objects.  Throws if the file does not exist.
    .PARAMETER Path
        Full path to the CSV report file.
    .OUTPUTS
        [PSCustomObject[]] Array of CSV row objects, or $null on error.
    .EXAMPLE
        $rows = Import-PDQReport -Path 'C:\Reports\Logged in User.csv'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -Path $Path)) { throw "Report not found: $Path" }
        $rows = Import-Csv -Path $Path -ErrorAction Stop
        return $rows
    }
    catch {
        try { Write-Log -Message "Import-PDQReport error: $_" -Level "Error" } catch {}
        return $null
    }
}

function Sanitize-PDQUsername {
    <#
    .SYNOPSIS
        Clean a raw PDQ username string for consistent lookups.
    .DESCRIPTION
        Trims whitespace and strips any parenthesised suffix (e.g. domain hints)
        that PDQ Inventory sometimes appends to user names.
    .PARAMETER Name
        Raw username string from the PDQ report.
    .OUTPUTS
        [string] Cleaned username, or $null if the input was blank.
    .EXAMPLE
        Sanitize-PDQUsername -Name '  jsmith (DOMAIN)  '
        # Returns 'jsmith'
    #>
    [CmdletBinding()]
    param(
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $clean = $Name.Trim()
    $parenIndex = $clean.IndexOf('(')
    if ($parenIndex -ge 0) { $clean = $clean.Substring(0, $parenIndex) }
    return $clean.Trim()
}

function Update-PDQCache {
    <#
    .SYNOPSIS
        Reload the in-memory PDQ Inventory cache from the latest CSV report.
    .DESCRIPTION
        Reads PDQ settings, locates the newest report file, imports the CSV,
        and rebuilds the global $PDQInventoryCache with computer-keyed and
        user-keyed lookup dictionaries.
    .PARAMETER ReportPath
        Optional explicit path to a report file.  When omitted the function
        discovers the latest file using the configured folder and pattern.
    .PARAMETER Force
        Reserved for future use; currently has no effect.
    .OUTPUTS
        [bool] $true if the cache was successfully updated, $false otherwise.
    .EXAMPLE
        Update-PDQCache
    .EXAMPLE
        Update-PDQCache -ReportPath 'C:\Reports\Logged in User.csv'
    #>
    [CmdletBinding()]
    param(
        [string]$ReportPath,

        [switch]$Force
    )

    try {
        $settings = Get-PDQSettings
        if (-not $settings.Enabled) { return $false }

        if ([string]::IsNullOrWhiteSpace($ReportPath)) {
            $ReportPath = Get-PDQLatestReportPath -ReportFolder $settings.ReportFolder -FilePattern $settings.ReportFilePattern
        }

        if (-not $ReportPath -or -not (Test-Path $ReportPath)) {
            try { Write-Log -Message "No PDQ report found (folder=$($settings.ReportFolder), pattern=$($settings.ReportFilePattern))." -Level "Warning" } catch {}
            return $false
        }

        $rows = Import-PDQReport -Path $ReportPath
        if (-not $rows) { return $false }

        # Determine usable columns
        $first = $rows | Select-Object -First 1
        $computerColumns = @('Computer Name','Name','Computer','Hostname','Host Name','Machine Name')
        $userColumns     = @('Computer Current User Name','Last Logged On User','Last LoggedOn User','User Logged On','Current Logged On User','Logged On User')
        $computerKey = $null
        foreach ($candidate in $computerColumns) {
            if ($first -and $first.PSObject.Properties.Name -contains $candidate) { $computerKey = $candidate; break }
        }
        if (-not $computerKey) { $computerKey = ($first.PSObject.Properties.Name | Select-Object -First 1) }

        $userKey = $null
        foreach ($candidate in $userColumns) {
            if ($first -and $first.PSObject.Properties.Name -contains $candidate) { $userKey = $candidate; break }
        }

        $dict = @{}
        $userToComputers = @{}

        foreach ($row in $rows) {
            $comp = $row.$computerKey
            if ([string]::IsNullOrWhiteSpace($comp)) { continue }
            $upperComp = $comp.ToUpperInvariant()
            $dict[$upperComp] = $row

            if ($userKey) {
                $rawUser = $row.$userKey
                $sanUser = Sanitize-PDQUsername -Name $rawUser
                if (-not [string]::IsNullOrWhiteSpace($sanUser)) {
                    $key = $sanUser.ToUpperInvariant()
                    if (-not $userToComputers.ContainsKey($key)) { $userToComputers[$key] = @() }
                    if ($userToComputers[$key] -notcontains $comp) {
                        $userToComputers[$key] += $comp
                    }
                }
            }
        }

        $global:PDQInventoryCache = [PSCustomObject]@{
            SourceFile         = $ReportPath
            LastLoaded         = Get-Date
            ComputerNameColumn = $computerKey
            UserNameColumn     = $userKey
            Data               = $dict
            UserToComputers    = $userToComputers
        }

        try { Write-Log -Message "PDQ cache loaded from $ReportPath with $($dict.Count) records" -Level "Info" } catch {}
        return $true
    }
    catch {
        try { Write-Log -Message "Update-PDQCache error: $_" -Level "Error" } catch {}
        return $false
    }
}

function Get-PDQInfoForComputer {
    <#
    .SYNOPSIS
        Look up cached PDQ report data for a single computer.
    .DESCRIPTION
        Returns the CSV row object stored in the global PDQ cache for the
        specified computer name.  Optionally triggers a cache refresh first.
    .PARAMETER ComputerName
        NetBIOS or hostname of the target computer (case-insensitive).
    .PARAMETER AutoRefresh
        When specified, calls Update-PDQCache before performing the lookup.
    .OUTPUTS
        [PSCustomObject] The cached row for the computer, or $null.
    .EXAMPLE
        Get-PDQInfoForComputer -ComputerName 'PC01' -AutoRefresh
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [switch]$AutoRefresh
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $null }

    try {
        if (-not $global:PDQInventoryCache -or $AutoRefresh) {
            Update-PDQCache | Out-Null
        }

        if (-not $global:PDQInventoryCache -or -not $global:PDQInventoryCache.Data) { return $null }

        $key = $ComputerName.ToUpperInvariant()
        if ($global:PDQInventoryCache.Data.ContainsKey($key)) {
            return $global:PDQInventoryCache.Data[$key]
        }
        return $null
    }
    catch {
        try { Write-Log -Message "Get-PDQInfoForComputer error for ${ComputerName}: $_" -Level "Warning" } catch {}
        return $null
    }
}

function Get-PDQUsersForComputer {
    <#
    .SYNOPSIS
        Return the logged-on user(s) for a given computer from the PDQ cache.
    .DESCRIPTION
        Retrieves the cached PDQ row for the computer and extracts the sanitised
        username from the user-name column.
    .PARAMETER ComputerName
        NetBIOS or hostname of the target computer (case-insensitive).
    .OUTPUTS
        [string[]] Array of usernames (typically one element), or empty array.
    .EXAMPLE
        Get-PDQUsersForComputer -ComputerName 'PC01'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        if (-not $global:PDQInventoryCache) { return @() }
        $row = Get-PDQInfoForComputer -ComputerName $ComputerName
        if (-not $row) { return @() }
        $userColumn = $global:PDQInventoryCache.UserNameColumn
        if ([string]::IsNullOrWhiteSpace($userColumn)) { return @() }
        $san = Sanitize-PDQUsername -Name $row.$userColumn
        if ([string]::IsNullOrWhiteSpace($san)) { return @() }
        return @($san)
    }
    catch { return @() }
}

function Get-PDQComputersForUser {
    <#
    .SYNOPSIS
        Return all computers associated with a user from the PDQ cache.
    .DESCRIPTION
        Looks up the user-to-computers dictionary built by Update-PDQCache and
        returns every computer the user was last logged on to.
    .PARAMETER Username
        Username to search for (case-insensitive, automatically sanitised).
    .OUTPUTS
        [string[]] Array of computer names, or empty array.
    .EXAMPLE
        Get-PDQComputersForUser -Username 'jsmith'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        if (-not $global:PDQInventoryCache) { return @() }
        $key = (Sanitize-PDQUsername -Name $Username)
        if ([string]::IsNullOrWhiteSpace($key)) { return @() }
        $upper = $key.ToUpperInvariant()
        if ($global:PDQInventoryCache.UserToComputers.ContainsKey($upper)) {
            return $global:PDQInventoryCache.UserToComputers[$upper]
        }
        return @()
    }
    catch { return @() }
}

function Show-PDQLatestReport {
    <#
    .SYNOPSIS
        Open the latest PDQ Inventory CSV report in the default application.
    .DESCRIPTION
        Resolves the newest report file using Get-PDQLatestReportPath and
        launches it via Start-Process.  Shows a message box when no report
        can be found.
    .OUTPUTS
        [bool] $true if the report was opened, $false otherwise.
    .EXAMPLE
        Show-PDQLatestReport
    #>
    [CmdletBinding()]
    param()

    try {
        $settings = Get-PDQSettings
        $path = Get-PDQLatestReportPath -ReportFolder $settings.ReportFolder -FilePattern $settings.ReportFilePattern
        if ($path -and (Test-Path $path)) {
            Start-Process -FilePath $path | Out-Null
            return $true
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "No PDQ report was found in $($settings.ReportFolder) matching $($settings.ReportFilePattern).",
                "PDQ Inventory",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $false
        }
    }
    catch {
        try { Write-Log -Message "Show-PDQLatestReport error: $_" -Level "Error" } catch {}
        return $false
    }
}

function Get-PDQInventoryCLISettings {
    <#
    .SYNOPSIS
        Load PDQ Inventory CLI settings from the global configuration.
    .DESCRIPTION
        Returns PDQ Inventory CLI configuration including executable path,
        cache timeout, and auto-query preferences.  Falls back to built-in
        defaults when the global $Settings object is missing or incomplete.
    .OUTPUTS
        [PSCustomObject] with properties Enabled, ExecutablePath,
        CacheTimeoutMinutes, AutoQueryOnSelection, AutoQueryOnSearch,
        and AutoQueryMaxResults.
    .EXAMPLE
        $cli = Get-PDQInventoryCLISettings
        $cli.ExecutablePath
    #>
    [CmdletBinding()]
    param()

    $defaults = [PSCustomObject]@{
        Enabled              = $false
        ExecutablePath       = "C:\Program Files (x86)\Admin Arsenal\PDQ Inventory\PDQInventory.exe"
        CacheTimeoutMinutes  = 15
        AutoQueryOnSelection = $false
        AutoQueryOnSearch    = $false
        AutoQueryMaxResults  = 5
    }

    try {
        $settingsObj = $null
        if ($global:Settings) { $settingsObj = $global:Settings }
        if ($settingsObj -and ($settingsObj.PSObject.Properties.Name -contains 'PDQ') -and
            ($settingsObj.PDQ.PSObject.Properties.Name -contains 'InventoryCLI')) {
            $cli = $settingsObj.PDQ.InventoryCLI
            return [PSCustomObject]@{
                Enabled              = $(if ($null -eq $cli.Enabled) { $defaults.Enabled } else { [bool]$cli.Enabled })
                ExecutablePath       = $(if ([string]::IsNullOrWhiteSpace($cli.ExecutablePath)) { $defaults.ExecutablePath } else { $cli.ExecutablePath })
                CacheTimeoutMinutes  = $(if ($null -eq $cli.CacheTimeoutMinutes) { $defaults.CacheTimeoutMinutes } else { [int]$cli.CacheTimeoutMinutes })
                AutoQueryOnSelection = $(if ($null -eq $cli.AutoQueryOnSelection) { $defaults.AutoQueryOnSelection } else { [bool]$cli.AutoQueryOnSelection })
                AutoQueryOnSearch    = $(if ($null -eq $cli.AutoQueryOnSearch) { $defaults.AutoQueryOnSearch } else { [bool]$cli.AutoQueryOnSearch })
                AutoQueryMaxResults  = $(if ($null -eq $cli.AutoQueryMaxResults) { $defaults.AutoQueryMaxResults } else { [int]$cli.AutoQueryMaxResults })
            }
        }
    }
    catch {
        try { Write-Log -Message "Error loading PDQ Inventory CLI settings: $_" -Level "Warning" } catch {}
    }

    return $defaults
}

function Test-PDQInventoryCLIAvailable {
    <#
    .SYNOPSIS
        Check whether the PDQ Inventory CLI executable is accessible.
    .DESCRIPTION
        Verifies that the CLI feature is enabled in settings and that
        PDQInventory.exe exists at the configured path.
    .OUTPUTS
        [bool] $true if the CLI is enabled and the executable exists.
    .EXAMPLE
        if (Test-PDQInventoryCLIAvailable) { Invoke-PDQGetComputer -ComputerName 'PC01' }
    #>
    [CmdletBinding()]
    param()

    try {
        $settings = Get-PDQInventoryCLISettings
        if (-not $settings.Enabled) { return $false }

        if ([string]::IsNullOrWhiteSpace($settings.ExecutablePath)) { return $false }

        return (Test-Path $settings.ExecutablePath)
    }
    catch {
        try { Write-Log -Message "Error checking PDQ Inventory CLI availability: $_" -Level "Warning" } catch {}
        return $false
    }
}

function Invoke-PDQGetComputer {
    <#
    .SYNOPSIS
        Query PDQ Inventory CLI for detailed information about a computer.
    .DESCRIPTION
        Executes PDQInventory.exe GetComputer for the target machine, parses the
        output into a structured object, and caches the result.  Returns cached
        data when available unless NoCache is specified.
    .PARAMETER ComputerName
        NetBIOS or hostname of the target computer.
    .PARAMETER NoCache
        When specified, bypasses the cache and forces a fresh CLI query.
    .OUTPUTS
        [PSCustomObject] Structured computer details, or $null on failure.
    .EXAMPLE
        Invoke-PDQGetComputer -ComputerName 'PC01'
    .EXAMPLE
        Invoke-PDQGetComputer -ComputerName 'PC01' -NoCache
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [switch]$NoCache
    )

    try {
        # Return cached result when allowed
        if (-not $NoCache) {
            $cached = Get-PDQCLICachedComputer -ComputerName $ComputerName
            if ($cached) {
                return $cached
            }
        }

        $settings = Get-PDQInventoryCLISettings

        if (-not $settings.Enabled) {
            return $null
        }

        if (-not (Test-Path $settings.ExecutablePath)) {
            try { Write-Log -Message "PDQ Inventory CLI executable not found at: $($settings.ExecutablePath)" -Level "Warning" } catch {}
            return $null
        }

        try { Write-Log -Message "Querying PDQ Inventory for computer '$ComputerName'" -Level "Info" } catch {}

        # Execute GetComputer command
        $output = & $settings.ExecutablePath GetComputer -computer $ComputerName 2>&1 | Out-String

        # Parse the output
        $result = Format-PDQComputerInfo -RawOutput $output

        # Persist parsed result for subsequent lookups
        if ($result) {
            Update-PDQCLICache -ComputerName $ComputerName -Data $result
        }

        return $result

    }
    catch {
        $errorMsg = $_.Exception.Message
        try { Write-Log -Message "Error querying PDQ Inventory for '$ComputerName': $errorMsg" -Level "Error" } catch {}
        return $null
    }
}

function Format-PDQComputerInfo {
    <#
    .SYNOPSIS
        Parse raw PDQ Inventory CLI output into a structured object.
    .DESCRIPTION
        Splits the text output from PDQInventory.exe GetComputer on newlines,
        extracts key-value pairs delimited by colons, and maps them to a
        well-known set of properties.
    .PARAMETER RawOutput
        Raw text output captured from the PDQ Inventory CLI.
    .OUTPUTS
        [PSCustomObject] with named properties for common fields plus a
        RawData hashtable containing every parsed key-value pair.
    .EXAMPLE
        $info = Format-PDQComputerInfo -RawOutput $cliOutput
        $info.IPAddress
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawOutput
    )

    try {
        if ([string]::IsNullOrWhiteSpace($RawOutput)) {
            return $null
        }
        
        # Detect common CLI licensing errors
        if ($RawOutput -match '(?i)requires\s+pdq\s+inventory\s+enterprise|enterprise\s+required|not\s+licensed|license\s+required') {
            return [PSCustomObject]@{
                ErrorMessage = "PDQ Inventory Enterprise license required for this command."
                RawOutput = $RawOutput
            }
        }

        # Parse key-value pairs from output
        $data = @{}
        $lines = $RawOutput -split "`r?`n"

        foreach ($line in $lines) {
            if ($line -match '^\s*([^:=]+?)\s*[:=]\s*(.+?)\s*$') {
                $key   = $matches[1].Trim()
                $value = $matches[2].Trim()
                $data[$key] = $value
            }
        }

        if ($data.Count -eq 0) {
            return $null
        }

        # Map parsed keys to a consistent property set
        return [PSCustomObject]@{
            Name             = $data['Name']
            HostName         = $data['Host Name']
            Online           = $data['Online']
            Uptime           = $data['Uptime']
            BootTime         = $data['Boot Time']
            CurrentUser      = $data['Current User']
            IPAddress        = $data['IP Address']
            MACAddress       = $data['MAC Address']
            TimeZone         = $data['Time Zone']
            OperatingSystem  = $data['Name']            # From Operating System section
            OSVersion        = $data['Version']
            OSRelease        = $data['SP / Release']
            OSInstalled      = $data['Installed']
            SerialNumber     = $data['Serial Number']
            SystemDrive      = $data['System Drive']
            PowerShellVersion = $data['PowerShell Version']
            Architecture     = $data['Architecture']
            NeedsReboot      = $data['Needs Reboot']
            ADPath           = $data['Path']            # From Active Directory section
            Domain           = $data['Domain']
            ADCreated        = $data['Created']
            Manufacturer     = $data['Manufacturer']    # From System section
            Model            = $data['Model']
            Memory           = $data['Memory']
            BIOSVersion      = $data['BIOS Version']
            BIOSManufacturer = $data['BIOS Manufacturer']
            RawData          = $data
        }

    }
    catch {
        try { Write-Log -Message "Error parsing PDQ Inventory output: $_" -Level "Error" } catch {}
        return $null
    }
}

function Get-PDQCLICachedComputer {
    <#
    .SYNOPSIS
        Retrieve cached CLI query data for a computer if still fresh.
    .DESCRIPTION
        Returns the previously cached PDQ Inventory CLI result for the given
        computer, provided the cache entry has not exceeded the configured
        CacheTimeoutMinutes threshold.
    .PARAMETER ComputerName
        NetBIOS or hostname of the target computer (case-insensitive).
    .OUTPUTS
        [PSCustomObject] Cached computer data, or $null if absent or stale.
    .EXAMPLE
        $cached = Get-PDQCLICachedComputer -ComputerName 'PC01'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        if (-not $global:PDQInventoryCLICache) {
            return $null
        }

        $key = $ComputerName.ToUpperInvariant()

        if (-not $global:PDQInventoryCLICache.ContainsKey($key)) {
            return $null
        }

        $cached = $global:PDQInventoryCLICache[$key]

        # Honour the configured staleness window
        $settings = Get-PDQInventoryCLISettings
        $timeout = New-TimeSpan -Minutes $settings.CacheTimeoutMinutes

        if ((Get-Date) -gt ($cached.Timestamp.Add($timeout))) {
            return $null
        }

        return $cached.Data

    }
    catch {
        try { Write-Log -Message "Error retrieving cached PDQ CLI data: $_" -Level "Warning" } catch {}
        return $null
    }
}

function Update-PDQCLICache {
    <#
    .SYNOPSIS
        Store a CLI query result in the global cache with a timestamp.
    .DESCRIPTION
        Adds or updates the entry for the specified computer in the global
        $PDQInventoryCLICache hashtable, recording the current time so
        staleness can be evaluated later.
    .PARAMETER ComputerName
        NetBIOS or hostname of the target computer.
    .PARAMETER Data
        The PSCustomObject returned by Format-PDQComputerInfo.
    .OUTPUTS
        None.
    .EXAMPLE
        Update-PDQCLICache -ComputerName 'PC01' -Data $computerInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data
    )

    try {
        # Lazily initialise the cache hashtable on first use
        if (-not $global:PDQInventoryCLICache) {
            $global:PDQInventoryCLICache = @{}
        }

        $key = $ComputerName.ToUpperInvariant()

        $global:PDQInventoryCLICache[$key] = [PSCustomObject]@{
            Data      = $Data
            Timestamp = Get-Date
        }

        try { Write-Log -Message "Cached PDQ CLI data for '$ComputerName'" -Level "Debug" } catch {}

    }
    catch {
        try { Write-Log -Message "Error caching PDQ CLI data: $_" -Level "Warning" } catch {}
    }
}

function Show-PDQCLIDialog {
    <#
    .SYNOPSIS
        Display a WinForms dialog showing real-time PDQ Inventory data for a computer.
    .DESCRIPTION
        Builds a resizable Form with a ListView that shows parsed PDQ Inventory
        CLI output grouped by category (System Status, Network, OS, Hardware,
        Active Directory).  Supports background prefetch polling and manual
        refresh.
    .PARAMETER ComputerName
        NetBIOS or hostname of the computer to query.
    .PARAMETER ParentForm
        Optional parent form used for centering the dialog.
    .OUTPUTS
        None.  The dialog is shown modally.
    .EXAMPLE
        Show-PDQCLIDialog -ComputerName 'PC01'
    .EXAMPLE
        Show-PDQCLIDialog -ComputerName 'PC01' -ParentForm $mainForm
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [System.Windows.Forms.Form]$ParentForm = $null
    )

    try {
        $dialog = New-Object System.Windows.Forms.Form
        $dialog.Text = "PDQ Inventory - $ComputerName"
        $dialog.Size = New-Object System.Drawing.Size(650, 550)
        $dialog.StartPosition = if ($ParentForm) { "CenterParent" } else { "CenterScreen" }
        $dialog.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        $dialog.MaximizeBox = $true
        $dialog.MinimizeBox = $false
        $dialog.MinimumSize = New-Object System.Drawing.Size(500, 400)

        $listView = New-Object System.Windows.Forms.ListView
        $listView.Location = New-Object System.Drawing.Point(10, 50)
        $listView.Size = New-Object System.Drawing.Size(610, 410)
        $listView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $listView.View = [System.Windows.Forms.View]::Details
        $listView.FullRowSelect = $true
        $listView.GridLines = $true
        $listView.Columns.Add("Property", 200) | Out-Null
        $listView.Columns.Add("Value", 390) | Out-Null
        $dialog.Controls.Add($listView)

        $lastShownTimestamp = $null

        $isInFlight = {
            try {
                if (-not $global:ADappPDQAutoQueryJobs) { return $false }
                foreach ($j in @($global:ADappPDQAutoQueryJobs)) {
                    try {
                        if ($j -and $j.ComputerName -eq $ComputerName -and $j.Handle -and (-not $j.Handle.IsCompleted)) { return $true }
                    } catch {}
                }
            } catch {}
            return $false
        }

        $getCacheEntry = {
            try {
                if ($global:PDQInventoryCLICache) {
                    return $global:PDQInventoryCLICache[$ComputerName.ToUpperInvariant()]
                }
            } catch {}
            return $null
        }

        $populateData = {
            param($fromCache = $true)
            $listView.Items.Clear()
            try {
                $data = $null
                $cacheEntry = $null
                try { $cacheEntry = (& $getCacheEntry) } catch { $cacheEntry = $null }

                # Prefer the raw cache entry to avoid freshness-check edge cases after async prefetch
                if ($fromCache -and $cacheEntry -and $cacheEntry.Data) {
                    $data = $cacheEntry.Data
                }
                elseif ($fromCache) {
                    try { $data = Get-PDQCLICachedComputer -ComputerName $ComputerName } catch { $data = $null }
                }
                if (-not $data) {
                    if (-not $fromCache) {
                        # Only perform a blocking CLI query when explicitly requested
                        $loadingItem = New-Object System.Windows.Forms.ListViewItem("Status")
                        $loadingItem.SubItems.Add("Querying PDQ Inventory...")
                        $loadingItem.ForeColor = [System.Drawing.Color]::Gray
                        $listView.Items.Add($loadingItem) | Out-Null
                        $dialog.Refresh()
                        $data = Invoke-PDQGetComputer -ComputerName $ComputerName
                        $listView.Items.Clear()
                    }
                    else {
                        $item = New-Object System.Windows.Forms.ListViewItem("No Data Cached")
                        $item.SubItems.Add("Click Refresh to query PDQ Inventory")
                        $item.ForeColor = [System.Drawing.Color]::Gray
                        $listView.Items.Add($item) | Out-Null
                        $statusLabel.Text = "Status: Waiting for PDQ data (background query may still be running)..."
                        $statusLabel.ForeColor = [System.Drawing.Color]::Orange
                        return $false
                    }
                }
                if ($data) {
                    if ($data.PSObject.Properties.Name -contains "ErrorMessage") {
                        $item = New-Object System.Windows.Forms.ListViewItem("PDQ Inventory")
                        $item.SubItems.Add($data.ErrorMessage) | Out-Null
                        $item.ForeColor = [System.Drawing.Color]::Red
                        $listView.Items.Add($item) | Out-Null
                        $statusLabel.Text = "Status: PDQ Inventory Enterprise license required"
                        $statusLabel.ForeColor = [System.Drawing.Color]::Red
                        return $true
                    }
                    if ($cacheEntry) {
                        $timeItem = New-Object System.Windows.Forms.ListViewItem("Data Retrieved")
                        $timeItem.SubItems.Add($cacheEntry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))
                        $timeItem.ForeColor = [System.Drawing.Color]::DarkGray
                        $listView.Items.Add($timeItem) | Out-Null
                        $separator = New-Object System.Windows.Forms.ListViewItem("")
                        $separator.SubItems.Add("")
                        $listView.Items.Add($separator) | Out-Null
                    }
                    $addedFieldCount = 0
                    $addField = {
                        param($label, $value, $color = $null)
                        if (-not [string]::IsNullOrWhiteSpace($value)) {
                            $item = New-Object System.Windows.Forms.ListViewItem($label)
                            $item.SubItems.Add([string]$value) | Out-Null
                            if ($color) { $item.ForeColor = $color }
                            $listView.Items.Add($item) | Out-Null
                            $script:addedFieldCount++
                        }
                    }
                    & $addField "═══ System Status ═══" "" ([System.Drawing.Color]::DarkBlue)
                    & $addField "Online" $data.Online
                    & $addField "Uptime" $data.Uptime
                    & $addField "Boot Time" $data.BootTime
                    & $addField "Needs Reboot" $data.NeedsReboot
                    & $addField "Current User" $data.CurrentUser
                    $listView.Items.Add((New-Object System.Windows.Forms.ListViewItem("", ""))) | Out-Null
                    & $addField "═══ Network ═══" "" ([System.Drawing.Color]::DarkBlue)
                    & $addField "IP Address" $data.IPAddress
                    & $addField "MAC Address" $data.MACAddress
                    & $addField "Time Zone" $data.TimeZone
                    $listView.Items.Add((New-Object System.Windows.Forms.ListViewItem("", ""))) | Out-Null
                    & $addField "═══ Operating System ═══" "" ([System.Drawing.Color]::DarkBlue)
                    & $addField "OS Version" $data.OSVersion
                    & $addField "OS Release" $data.OSRelease
                    & $addField "Architecture" $data.Architecture
                    & $addField "System Drive" $data.SystemDrive
                    & $addField "PowerShell Version" $data.PowerShellVersion
                    $listView.Items.Add((New-Object System.Windows.Forms.ListViewItem("", ""))) | Out-Null
                    & $addField "═══ Hardware ═══" "" ([System.Drawing.Color]::DarkBlue)
                    & $addField "Manufacturer" $data.Manufacturer
                    & $addField "Model" $data.Model
                    & $addField "Serial Number" $data.SerialNumber
                    & $addField "Memory" $data.Memory
                    & $addField "BIOS Version" $data.BIOSVersion
                    & $addField "BIOS Manufacturer" $data.BIOSManufacturer
                    $listView.Items.Add((New-Object System.Windows.Forms.ListViewItem("", ""))) | Out-Null
                    & $addField "═══ Active Directory ═══" "" ([System.Drawing.Color]::DarkBlue)
                    & $addField "Domain" $data.Domain
                    & $addField "AD Path" $data.ADPath
                    & $addField "AD Created" $data.ADCreated
                    if ($addedFieldCount -eq 0 -and $data.RawData -and $data.RawData.Count -gt 0) {
                        $rawHeader = New-Object System.Windows.Forms.ListViewItem("Raw Fields")
                        $rawHeader.SubItems.Add("") | Out-Null
                        $rawHeader.ForeColor = [System.Drawing.Color]::DarkBlue
                        $listView.Items.Add($rawHeader) | Out-Null
                        foreach ($key in ($data.RawData.Keys | Sort-Object)) {
                            $value = $data.RawData[$key]
                            if (-not [string]::IsNullOrWhiteSpace($value)) {
                                $rawItem = New-Object System.Windows.Forms.ListViewItem([string]$key)
                                $rawItem.SubItems.Add([string]$value) | Out-Null
                                $listView.Items.Add($rawItem) | Out-Null
                            }
                        }
                    }
                    $statusLabel.Text = "Status: Data loaded successfully"
                    $statusLabel.ForeColor = [System.Drawing.Color]::Green
                    return $true
                }
                else {
                    $item = New-Object System.Windows.Forms.ListViewItem("No Data Available")
                    $item.SubItems.Add("Unable to retrieve information from PDQ Inventory")
                    $item.ForeColor = [System.Drawing.Color]::Red
                    $listView.Items.Add($item) | Out-Null
                    $statusLabel.Text = "Status: No data available"
                    $statusLabel.ForeColor = [System.Drawing.Color]::Red
                    return $false
                }
            }
            catch {
                try { Write-Log -Message "Error populating PDQ CLI dialog: $_" -Level "Error" } catch {}
                $listView.Items.Clear()
                $errorItem = New-Object System.Windows.Forms.ListViewItem("Error")
                $errorItem.SubItems.Add($_.Exception.Message)
                $errorItem.ForeColor = [System.Drawing.Color]::Red
                $listView.Items.Add($errorItem) | Out-Null
                $statusLabel.Text = "Status: Error loading data"
                $statusLabel.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        }

        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Location = New-Object System.Drawing.Point(10, 10)
        $statusLabel.Size = New-Object System.Drawing.Size(610, 20)
        $statusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $statusLabel.Text = "Status: Loading..."
        $statusLabel.ForeColor = [System.Drawing.Color]::Gray
        $dialog.Controls.Add($statusLabel)

        $instructionLabel = New-Object System.Windows.Forms.Label
        $instructionLabel.Location = New-Object System.Drawing.Point(10, 30)
        $instructionLabel.Size = New-Object System.Drawing.Size(610, 15)
        $instructionLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $instructionLabel.Text = "Real-time data from PDQ Inventory CLI"
        $instructionLabel.Font = New-Object System.Drawing.Font($instructionLabel.Font.FontFamily, 8)
        $instructionLabel.ForeColor = [System.Drawing.Color]::DarkGray
        $dialog.Controls.Add($instructionLabel)

        $refreshButton = New-Object System.Windows.Forms.Button
        $refreshButton.Text = "Refresh"
        $refreshButton.Size = New-Object System.Drawing.Size(90, 28)
        $refreshButton.Location = New-Object System.Drawing.Point(440, 470)
        $refreshButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $refreshButton.Add_Click({
            try {
                # If fresh data arrived since the dialog opened, show it immediately
                $key = $ComputerName.ToUpperInvariant()
                $hasCache = $false
                try { $hasCache = [bool]($global:PDQInventoryCLICache -and $global:PDQInventoryCLICache.ContainsKey($key)) } catch { $hasCache = $false }
                if ($hasCache) {
                    $statusLabel.Text = "Status: Loading cached data..."
                    $statusLabel.ForeColor = [System.Drawing.Color]::Gray
                    [void](& $populateData $true)
                    return
                }

                # Avoid a second blocking query when ADapp already has one running in the background
                $inFlight = $false
                try {
                    if ($global:ADappPDQAutoQueryJobs) {
                        foreach ($j in @($global:ADappPDQAutoQueryJobs)) {
                            try {
                                if ($j -and $j.ComputerName -eq $ComputerName -and $j.Handle -and (-not $j.Handle.IsCompleted)) {
                                    $inFlight = $true
                                    break
                                }
                            } catch {}
                        }
                    }
                } catch {}

                if ($inFlight) {
                    $statusLabel.Text = "Status: PDQ query already running in background... waiting for results"
                    $statusLabel.ForeColor = [System.Drawing.Color]::Orange
                    try { if (-not $autoRefreshTimer.Enabled) { $autoRefreshTimer.Start() } } catch {}
                    return
                }

                # Perform an explicit (blocking) refresh query
                $refreshButton.Enabled = $false
                $statusLabel.Text = "Status: Refreshing..."
                $statusLabel.ForeColor = [System.Drawing.Color]::Orange
                [void](& $populateData $false)
            }
            finally {
                $refreshButton.Enabled = $true
            }
        })
        $dialog.Controls.Add($refreshButton)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = "Close"
        $closeButton.Size = New-Object System.Drawing.Size(80, 28)
        $closeButton.Location = New-Object System.Drawing.Point(540, 470)
        $closeButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $closeButton.Add_Click({ $dialog.Close() })
        $dialog.Controls.Add($closeButton)

        # Poll for background prefetch results so the dialog auto-populates
        $autoRefreshTimer = New-Object System.Windows.Forms.Timer
        $autoRefreshTimer.Interval = 500
        $watchStart = Get-Date
        $autoRefreshTimer.Add_Tick({
            try {
                # Safety: stop after 30 s to prevent runaway polling
                if (((Get-Date) - $watchStart).TotalSeconds -gt 30) {
                    $autoRefreshTimer.Stop()
                    $statusLabel.Text = "Status: Still waiting for PDQ data (try Refresh)"
                    $statusLabel.ForeColor = [System.Drawing.Color]::Orange
                    return
                }
                $entry = $null
                try { $entry = (& $getCacheEntry) } catch { $entry = $null }
                $inFlight = $false
                try { $inFlight = [bool](& $isInFlight) } catch { $inFlight = $false }

                # Keep polling while the background query is still running and cache has not been refreshed
                if ($inFlight) {
                    if ($entry -and $entry.Timestamp -and $lastShownTimestamp -and ($entry.Timestamp -le $lastShownTimestamp)) {
                        $statusLabel.Text = "Status: Waiting for updated PDQ data (background query running)..."
                        $statusLabel.ForeColor = [System.Drawing.Color]::Orange
                        return
                    }
                }

                # Reload when data has never been shown or when the timestamp changed
                $shouldReload = $false
                if (-not $lastShownTimestamp) { $shouldReload = $true }
                elseif (-not $entry -or -not $entry.Timestamp) { $shouldReload = $true }
                elseif ($entry.Timestamp -gt $lastShownTimestamp) { $shouldReload = $true }

                if ($shouldReload) {
                    $loadedNow = $false
                    try { $loadedNow = [bool](& $populateData $true) } catch { $loadedNow = $false }
                    if ($loadedNow -and -not $inFlight) {
                        $autoRefreshTimer.Stop()
                    }
                }
                else {
                    if (-not $inFlight) { $autoRefreshTimer.Stop() }
                }
            } catch {}
        })

        $dialog.Add_FormClosed({
            try { $autoRefreshTimer.Stop() } catch {}
            try { $autoRefreshTimer.Dispose() } catch {}
        })

        $loaded = $false
        try { $loaded = [bool](& $populateData $true) } catch { $loaded = $false }
        # Start polling when there is no cached data yet or a background query is in progress
        try {
            $inFlightNow = [bool](& $isInFlight)
            if (-not $loaded -or $inFlightNow) {
                try { $watchStart = Get-Date; $autoRefreshTimer.Start() } catch {}
            }
        } catch {}

        if ($ParentForm) { [void]$dialog.ShowDialog($ParentForm) } else { [void]$dialog.ShowDialog() }
    }
    catch {
        try { Write-Log -Message "Error showing PDQ CLI dialog: $_" -Level "Error" } catch {}
        [System.Windows.Forms.MessageBox]::Show("Error displaying PDQ Inventory data: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────────────

Export-ModuleMember -Function Get-PDQSettings, Get-PDQLatestReportPath, Import-PDQReport, Update-PDQCache, Get-PDQInfoForComputer, Get-PDQUsersForComputer, Get-PDQComputersForUser, Show-PDQLatestReport, Get-PDQInventoryCLISettings, Test-PDQInventoryCLIAvailable, Invoke-PDQGetComputer, Format-PDQComputerInfo, Get-PDQCLICachedComputer, Update-PDQCLICache, Show-PDQCLIDialog
