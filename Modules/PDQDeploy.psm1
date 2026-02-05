#Requires -Version 5.1
<#
.SYNOPSIS
    PDQ Deploy integration module for ADapp.
.DESCRIPTION
    Provides functions to load PDQ Deploy settings, query available packages
    (with local caching), test executable availability, invoke package
    deployments, and display deployment result dialogs.
.NOTES
    Module: PDQDeploy
    Author: ADapp Team
    Requires: PDQ Deploy CLI (PDQDeploy.exe)
#>

#region Functions

function Get-PDQDeploySettings {
    <#
    .SYNOPSIS
        Loads PDQ Deploy settings from the application settings object.
    .DESCRIPTION
        Reads the PDQ.Deploy section of $global:Settings and returns a
        normalised object with Enabled, ExecutablePath, and Packages properties.
        Falls back to sensible defaults when settings are missing.
    .OUTPUTS
        PSCustomObject
        An object with Enabled (bool), ExecutablePath (string), and
        Packages (string[]) properties.
    .EXAMPLE
        $settings = Get-PDQDeploySettings
    #>
    [CmdletBinding()]
    param ()

    $defaults = [PSCustomObject]@{
        Enabled        = $false
        ExecutablePath = "C:\Program Files (x86)\Admin Arsenal\PDQ Deploy\PDQDeploy.exe"
        Packages       = @()
    }

    try {
        $settingsObj = $null
        if ($global:Settings) { $settingsObj = $global:Settings }
        if ($settingsObj -and ($settingsObj.PSObject.Properties.Name -contains 'PDQ') -and
            ($settingsObj.PDQ.PSObject.Properties.Name -contains 'Deploy')) {
            $deploy = $settingsObj.PDQ.Deploy

            # Normalise packages to an array
            $packageList = @()
            if ($deploy.PSObject.Properties.Name -contains 'Packages' -and $deploy.Packages) {
                if ($deploy.Packages -is [array]) {
                    $packageList = $deploy.Packages
                }
                else {
                    $packageList = @($deploy.Packages)
                }
            }


            return [PSCustomObject]@{
                Enabled        = $(if ($null -eq $deploy.Enabled) { $defaults.Enabled } else { [bool]$deploy.Enabled })
                ExecutablePath = $(if ([string]::IsNullOrWhiteSpace($deploy.ExecutablePath)) { $defaults.ExecutablePath } else { $deploy.ExecutablePath })
                Packages       = $packageList
            }
        }
    }
    catch {
        try { Write-Log -Message "Error loading PDQ Deploy settings: $_" -Level "Warning" } catch { }
    }

    return $defaults
}

function Get-PDQDeployPackageNames {
    <#
    .SYNOPSIS
        Retrieves all PDQ Deploy package names using PDQDeploy.exe.
    .DESCRIPTION
        Invokes PDQDeploy.exe with the GetPackageNames verb and parses the
        output (one package per line) into a string array.
    .PARAMETER ExecutablePath
        Optional override path to PDQDeploy.exe. When omitted the configured
        path from Get-PDQDeploySettings is used.
    .OUTPUTS
        System.String[]
        An array of package names, or an empty array on failure.
    .EXAMPLE
        Get-PDQDeployPackageNames
    .EXAMPLE
        Get-PDQDeployPackageNames -ExecutablePath "D:\Tools\PDQDeploy.exe"
    #>
    [CmdletBinding()]
    param (
        [string]$ExecutablePath
    )

    try {
        $settings = Get-PDQDeploySettings
        $exe = if (-not [string]::IsNullOrWhiteSpace($ExecutablePath)) { $ExecutablePath } else { $settings.ExecutablePath }

        if ([string]::IsNullOrWhiteSpace($exe)) { return @() }
        if (-not (Test-Path $exe)) { return @() }

        # PDQDeploy.exe GetPackageNames prints one package per line
        $output = & $exe GetPackageNames 2>&1
        $text   = ($output | Out-String)

        $lines = @($text -split "`r?`n") |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        return @($lines)
    }
    catch {
        try { Write-Log -Message "Get-PDQDeployPackageNames error: $_" -Level "Warning" } catch { }
        return @()
    }
}

#region Package cache helpers

function Get-PDQDeployPackageCachePath {
    <#
    .SYNOPSIS
        Returns the file path used for the local package-name cache.
    .OUTPUTS
        System.String
        The full path to the cache JSON file, or $null on error.
    #>
    [CmdletBinding()]
    param ()

    try {
        $dataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        try {
            if (-not (Test-Path $dataPath)) {
                New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
            }
        } catch { }
        return (Join-Path -Path $dataPath -ChildPath "pdq-deploy-packages-cache.json")
    }
    catch {
        return $null
    }
}

function Get-PDQDeployPackageCacheTimeoutMinutes {
    <#
    .SYNOPSIS
        Returns the configured cache timeout in minutes.
    .DESCRIPTION
        Reads Settings.PDQ.Deploy.PackageCacheTimeoutMinutes if available,
        otherwise defaults to 60 minutes.
    .OUTPUTS
        System.Int32
    #>
    [CmdletBinding()]
    param ()

    try {
        $settingsObj = $null
        if ($global:Settings) { $settingsObj = $global:Settings }
        if ($settingsObj -and $settingsObj.PDQ -and $settingsObj.PDQ.Deploy -and
            ($settingsObj.PDQ.Deploy.PSObject.Properties.Name -contains 'PackageCacheTimeoutMinutes')) {
            $v = $settingsObj.PDQ.Deploy.PackageCacheTimeoutMinutes
            if ($v -is [int] -and $v -gt 0) { return [int]$v }
            if ($v -is [string] -and ($v -as [int]) -gt 0) { return [int]$v }
        }
    } catch { }
    return 60
}

function Read-PDQDeployPackageCache {
    <#
    .SYNOPSIS
        Reads the local package-name cache from disk.
    .OUTPUTS
        PSCustomObject
        An object with Timestamp (datetime), Packages (string[]), and Path
        (string) properties, or $null if the cache does not exist or is invalid.
    #>
    [CmdletBinding()]
    param ()

    try {
        $path = Get-PDQDeployPackageCachePath
        if ([string]::IsNullOrWhiteSpace($path)) { return $null }
        if (-not (Test-Path $path)) { return $null }

        $raw = Get-Content -Path $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop

        $ts   = $null
        try { if ($obj -and $obj.Timestamp) { $ts = [datetime]$obj.Timestamp } } catch { $ts = $null }
        $pkgs = @()
        try { if ($obj -and $obj.Packages) { $pkgs = @($obj.Packages) } } catch { $pkgs = @() }

        return [PSCustomObject]@{
            Timestamp = $ts
            Packages  = $pkgs
            Path      = $path
        }
    }
    catch {
        try { Write-Log -Message "Read-PDQDeployPackageCache error: $_" -Level "Warning" } catch { }
        return $null
    }
}

function Write-PDQDeployPackageCache {
    <#
    .SYNOPSIS
        Writes package names to the local cache file.
    .PARAMETER Packages
        The package names to persist.
    .OUTPUTS
        System.Boolean
        $true if the cache was written successfully; $false otherwise.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Packages
    )

    try {
        $path = Get-PDQDeployPackageCachePath
        if ([string]::IsNullOrWhiteSpace($path)) { return $false }

        $payload = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Packages  = @($Packages)
        }

        $json = $payload | ConvertTo-Json -Depth 4
        Set-Content -Path $path -Value $json -Encoding UTF8 -Force
        return $true
    }
    catch {
        try { Write-Log -Message "Write-PDQDeployPackageCache error: $_" -Level "Warning" } catch { }
        return $false
    }
}

#endregion Package cache helpers

function Get-PDQDeployPackagesCached {
    <#
    .SYNOPSIS
        Returns PDQ Deploy package names, using a local cache when possible.
    .DESCRIPTION
        Checks the local cache first. If the cache is fresh (within the
        configured timeout) it is returned immediately; otherwise the cache is
        refreshed by querying PDQDeploy.exe.
    .PARAMETER ForceRefresh
        When specified, bypasses the cache and queries the executable directly.
    .OUTPUTS
        System.String[]
        An array of package names.
    .EXAMPLE
        Get-PDQDeployPackagesCached
    .EXAMPLE
        Get-PDQDeployPackagesCached -ForceRefresh
    #>
    [CmdletBinding()]
    param (
        [switch]$ForceRefresh
    )

    try {
        $timeoutMin = Get-PDQDeployPackageCacheTimeoutMinutes
        $cache = $null
        if (-not $ForceRefresh) { $cache = Read-PDQDeployPackageCache }

        $isFresh = $false
        try {
            if ($cache -and $cache.Timestamp -and $cache.Packages -and $cache.Packages.Count -gt 0) {
                $age = (New-TimeSpan -Start $cache.Timestamp -End (Get-Date)).TotalMinutes
                if ($age -le $timeoutMin) { $isFresh = $true }
            }
        } catch { $isFresh = $false }

        if ($isFresh) { return @($cache.Packages) }

        # Cache is stale or missing — refresh from the executable
        $pkgs = Get-PDQDeployPackageNames
        if ($pkgs -and $pkgs.Count -gt 0) {
            Write-PDQDeployPackageCache -Packages $pkgs | Out-Null
        }
        return @($pkgs)
    }
    catch {
        try { Write-Log -Message "Get-PDQDeployPackagesCached error: $_" -Level "Warning" } catch { }
        return @()
    }
}

function Test-PDQDeployAvailable {
    <#
    .SYNOPSIS
        Checks if PDQ Deploy is enabled and the executable exists.
    .DESCRIPTION
        Returns $true only when the PDQ Deploy integration is enabled in
        settings and the configured executable path exists on disk.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        if (Test-PDQDeployAvailable) { Write-Host "PDQ Deploy ready" }
    #>
    [CmdletBinding()]
    param ()

    try {
        $settings = Get-PDQDeploySettings
        if (-not $settings.Enabled) { return $false }
        if ([string]::IsNullOrWhiteSpace($settings.ExecutablePath)) { return $false }
        return (Test-Path $settings.ExecutablePath)
    }
    catch {
        try { Write-Log -Message "Error checking PDQ Deploy availability: $_" -Level "Warning" } catch { }
        return $false
    }
}

function Invoke-PDQDeployPackage {
    <#
    .SYNOPSIS
        Deploys a PDQ Deploy package to a target computer.
    .DESCRIPTION
        Invokes PDQDeploy.exe to deploy the specified package to the target
        computer and parses the output for a deployment ID and confirmation.
    .PARAMETER PackageName
        Name of the package to deploy (must exist in PDQ Deploy).
    .PARAMETER ComputerName
        Target computer name.
    .OUTPUTS
        PSCustomObject
        An object with Success (bool), Error (string), DeploymentID (string),
        Package (string), Targets (string), TargetCount (int), and
        RawOutput (string) properties.
    .EXAMPLE
        Invoke-PDQDeployPackage -PackageName "RDP Patch All Versions" -ComputerName "PC01"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        $settings = Get-PDQDeploySettings

        if (-not $settings.Enabled) {
            return [PSCustomObject]@{
                Success      = $false
                Error        = "PDQ Deploy integration is disabled in settings"
                DeploymentID = $null
                Package      = $PackageName
                Targets      = $ComputerName
            }
        }

        if (-not (Test-Path $settings.ExecutablePath)) {
            return [PSCustomObject]@{
                Success      = $false
                Error        = "PDQ Deploy executable not found at: $($settings.ExecutablePath)"
                DeploymentID = $null
                Package      = $PackageName
                Targets      = $ComputerName
            }
        }

        try { Write-Log -Message "Deploying package '$PackageName' to '$ComputerName'" -Level "Info" } catch { }

        $output     = & $settings.ExecutablePath Deploy $PackageName -Targets $ComputerName 2>&1
        $outputText = $output | Out-String
        $success    = $outputText -match "Deployment Started"

        # Extract deployment ID if present
        $deploymentID = $null
        if ($outputText -match "ID\s*:\s*(\d+)") {
            $deploymentID = $matches[1]
        }

        # Extract target count if present
        $targetCount = 1
        if ($outputText -match "Targets:\s*(\d+)") {
            $targetCount = $matches[1]
        }

        try {
            if ($success) {
                Write-Log -Message "Deployment started successfully. ID: $deploymentID" -Level "Info"
            }
            else {
                Write-Log -Message "Deployment command executed but no confirmation received. Output: $outputText" -Level "Warning"
            }
        } catch { }

        return [PSCustomObject]@{
            Success      = $success
            Error        = $(if (-not $success) { "Deployment command did not return expected confirmation" } else { $null })
            DeploymentID = $deploymentID
            Package      = $PackageName
            Targets      = $ComputerName
            TargetCount  = $targetCount
            RawOutput    = $outputText
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        try { Write-Log -Message "Error deploying package '$PackageName': $errorMsg" -Level "Error" } catch { }

        return [PSCustomObject]@{
            Success      = $false
            Error        = $errorMsg
            DeploymentID = $null
            Package      = $PackageName
            Targets      = $ComputerName
        }
    }
}

function Show-DeploymentResult {
    <#
    .SYNOPSIS
        Displays a deployment confirmation or error dialog.
    .DESCRIPTION
        Shows a message box summarising the deployment result including the
        deployment ID, package name, and target count.
    .PARAMETER Result
        Deployment result object returned by Invoke-PDQDeployPackage.
    .OUTPUTS
        None
    .EXAMPLE
        $result = Invoke-PDQDeployPackage -PackageName "Patch" -ComputerName "PC01"
        Show-DeploymentResult -Result $result
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Result
    )

    try {
        if ($Result.Success) {
            $message = "Deployment Started`n`n"
            if ($Result.DeploymentID) {
                $message += "ID: $($Result.DeploymentID)`n"
            }
            $message += "Package: $($Result.Package)`n"
            $message += "Targets: $($Result.TargetCount)"

            [System.Windows.Forms.MessageBox]::Show(
                $message,
                "PDQ Deploy",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        }
        else {
            $message  = "Deployment Failed`n`n"
            $message += "Package: $($Result.Package)`n"
            $message += "Target: $($Result.Targets)`n`n"
            $message += "Error: $($Result.Error)"

            [System.Windows.Forms.MessageBox]::Show(
                $message,
                "PDQ Deploy Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    }
    catch {
        try { Write-Log -Message "Error showing deployment result: $_" -Level "Error" } catch { }
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-PDQDeploySettings, Get-PDQDeployPackageNames,
    Get-PDQDeployPackagesCached, Test-PDQDeployAvailable,
    Invoke-PDQDeployPackage, Show-DeploymentResult
