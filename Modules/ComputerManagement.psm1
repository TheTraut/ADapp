#Requires -Version 5.1
<#
.SYNOPSIS
    Computer management module for ADapp.
.DESCRIPTION
    Provides functions for testing computer connectivity, retrieving AD computer
    details, and reading remote registry values.
.NOTES
    Module: ComputerManagement
    Author: ADapp Team
    Requires: ActiveDirectory module
#>

#region Functions

function Test-ComputerOnline {
    <#
    .SYNOPSIS
        Tests if a computer is online by pinging it.
    .DESCRIPTION
        Sends a single ICMP ping to the specified computer and returns whether
        it responded. Domain-qualified names are automatically stripped to the
        short hostname before testing.
    .PARAMETER ComputerName
        The computer name to test. Domain suffixes are stripped automatically.
    .OUTPUTS
        System.Boolean
        $true if the computer responded to the ping; $false otherwise.
    .EXAMPLE
        Test-ComputerOnline -ComputerName "WORKSTATION01"
    .EXAMPLE
        if (Test-ComputerOnline -ComputerName "PC-1234") { Write-Host "Online" }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Strip domain suffix if present (e.g. "PC01.contoso.com" → "PC01")
        $ComputerName = $ComputerName.Split('.')[0]

        $result = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
        return $result
    }
    catch {
        return $false
    }
}

function Get-ComputerDetails {
    <#
    .SYNOPSIS
        Gets detailed information about an AD computer.
    .DESCRIPTION
        Retrieves comprehensive computer properties from Active Directory
        including OS information, OU path, online status, and timestamps.
        Domain-qualified names are automatically stripped to the short hostname.
    .PARAMETER ComputerName
        The computer name to look up. Domain suffixes are stripped automatically.
    .OUTPUTS
        System.Collections.Hashtable
        A hashtable containing: Name, FullName, Description, OperatingSystem,
        OSVersion, OUPath, DistinguishedName, IsEnabled, IsOnline, LastLogon,
        Created, Modified, IPv4Address, and ManagedBy.
    .EXAMPLE
        Get-ComputerDetails -ComputerName "WORKSTATION01"
    .EXAMPLE
        $details = Get-ComputerDetails -ComputerName "PC-1234"
        $details.OperatingSystem
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Strip domain suffix if present
        $ComputerName = $ComputerName.Split('.')[0]

        $computer = Get-ADComputer -Identity $ComputerName -Properties *

        # Extract the OU path from the CanonicalName by removing the leaf (computer name)
        $OUPath    = $computer.CanonicalName
        $NamePart  = $OUPath.Split('/')[-1]
        $OU        = $OUPath.Replace("/$NamePart", '')

        $isOnline = Test-ComputerOnline -ComputerName $ComputerName

        return @{
            Name              = $ComputerName
            FullName          = $computer.DNSHostName
            Description       = $computer.Description
            OperatingSystem   = $computer.OperatingSystem
            OSVersion         = $computer.OperatingSystemVersion
            OUPath            = $OU
            DistinguishedName = $computer.DistinguishedName
            IsEnabled         = $computer.Enabled
            IsOnline          = $isOnline
            LastLogon         = if ($computer.lastLogon) { [datetime]::FromFileTime($computer.lastLogon) } else { $null }
            Created           = $computer.whenCreated
            Modified          = $computer.whenChanged
            IPv4Address       = $computer.IPv4Address
            ManagedBy         = $computer.ManagedBy
        }
    }
    catch {
        throw "Error getting computer details: $_"
    }
}

function Get-RegistryKey {
    <#
    .SYNOPSIS
        Gets a registry key value from a remote computer.
    .DESCRIPTION
        Opens a remote registry connection to the specified computer and reads
        the value at the given hive, key path, and value name. Returns $null if
        the key or value does not exist.
    .PARAMETER ComputerName
        The remote computer to query.
    .PARAMETER Hive
        The registry hive to open (LocalMachine, CurrentUser, ClassesRoot,
        Users, or CurrentConfig).
    .PARAMETER KeyPath
        The registry key path beneath the hive.
    .PARAMETER ValueName
        The name of the value to retrieve.
    .OUTPUTS
        System.Object
        The registry value, or $null if not found.
    .EXAMPLE
        Get-RegistryKey -ComputerName "PC01" -Hive LocalMachine `
            -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion" -ValueName "ProgramFilesDir"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('LocalMachine', 'CurrentUser', 'ClassesRoot', 'Users', 'CurrentConfig')]
        [string]$Hive,

        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    try {
        # Map friendly hive names to .NET RegistryHive enum values
        $hiveMap = @{
            'LocalMachine'  = [Microsoft.Win32.RegistryHive]::LocalMachine
            'CurrentUser'   = [Microsoft.Win32.RegistryHive]::CurrentUser
            'ClassesRoot'   = [Microsoft.Win32.RegistryHive]::ClassesRoot
            'Users'         = [Microsoft.Win32.RegistryHive]::Users
            'CurrentConfig' = [Microsoft.Win32.RegistryHive]::CurrentConfig
        }

        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveMap[$Hive], $ComputerName)
        $key = $reg.OpenSubKey($KeyPath)

        if ($key) {
            $value = $key.GetValue($ValueName)
            $key.Close()
            $reg.Close()
            return $value
        }

        $reg.Close()
        return $null
    }
    catch {
        Write-Warning "Error reading registry from ${ComputerName}: $_"
        return $null
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Test-ComputerOnline, Get-ComputerDetails, Get-RegistryKey
