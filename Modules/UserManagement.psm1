#Requires -Version 5.1
<#
.SYNOPSIS
    User management module for ADapp.
.DESCRIPTION
    Provides functions for retrieving Active Directory user details including
    account properties, group memberships, and logon timestamps. Also supports
    querying logged-in users on remote computers via WMI with quser fallback.
.NOTES
    Module: UserManagement
    Author: ADapp Team
    Requires: ActiveDirectory module
#>

#region Functions

function Get-UserDetails {
    <#
    .SYNOPSIS
        Gets detailed information about an AD user.
    .DESCRIPTION
        Retrieves comprehensive user properties from Active Directory including
        account status, organizational unit, group memberships, and logon
        timestamps. Accepts SamAccountName, UPN (user@domain), or
        DOMAIN\username formats which are automatically normalized.
    .PARAMETER username
        The username (SamAccountName) to look up. UPN and DOMAIN\username
        formats are stripped to the bare SamAccountName before querying.
    .OUTPUTS
        System.Collections.Hashtable
        A hashtable containing: Username, FullName, Title, Department, Phone,
        OUPath, IsLocked, IsEnabled, Groups, LastLogon, and PwdLastSet.
    .EXAMPLE
        Get-UserDetails -username "jsmith"
    .EXAMPLE
        Get-UserDetails -username "jsmith@contoso.com"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )

    try {
        # Strip UPN suffix (@domain) or DOMAIN\ prefix to get the SamAccountName
        if ($username) { $username = $username.Split('@')[0].Split('\\')[-1] }

        # Retrieve user with all required properties in a single AD call
        $user = Get-ADUser -Identity $username -Properties CanonicalName, LockedOut, Enabled, Title, Department, MemberOf, telephoneNumber, lastLogon, pwdLastSet

        # Extract the OU path from the CanonicalName by removing the leaf (username)
        $OUPath = $user.CanonicalName
        $NamePart = $OUPath.Split('/')[-1]
        $OU = $OUPath.Replace("/$NamePart", '')

        return @{
            Username   = $username
            FullName   = "$($user.GivenName) $($user.Surname)"
            Title      = $user.Title
            Department = $user.Department
            Phone      = $user.telephoneNumber
            OUPath     = $OU
            IsLocked   = $user.LockedOut
            IsEnabled  = $user.Enabled
            Groups     = $user.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }
            LastLogon  = if ($user.lastLogon) { [datetime]::FromFileTime($user.lastLogon) } else { $null }
            PwdLastSet = if ($user.pwdLastSet) { [datetime]::FromFileTime($user.pwdLastSet) } else { $null }
        }
    }
    catch {
        throw "Error getting user details: $_"
    }
}

function Get-LoggedInUsers {
    <#
    .SYNOPSIS
        Gets logged-in users for a remote computer.
    .DESCRIPTION
        Queries a remote computer for currently logged-in users. Attempts WMI
        (CIM) first for reliability, then falls back to the quser command-line
        utility if WMI is unavailable or returns an error.
    .PARAMETER ComputerName
        The name of the remote computer to query.
    .OUTPUTS
        System.Object[]
        An array of PSCustomObjects with UserName, ComputerName, and Source
        ('WMI' or 'QUser') properties.
    .EXAMPLE
        Get-LoggedInUsers -ComputerName "WORKSTATION01"
    .EXAMPLE
        $users = Get-LoggedInUsers -ComputerName "PC-1234"
        $users | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        $loggedInUsers = @()

        # Primary method: WMI via CIM instance
        try {
            $sessions = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
            if ($sessions.UserName) {
                $loggedInUsers += [PSCustomObject]@{
                    UserName     = $sessions.UserName
                    ComputerName = $ComputerName
                    Source       = 'WMI'
                }
            }
        }
        catch {
            # Fallback method: quser command-line utility
            try {
                $quserOutput = quser /server:$ComputerName 2>$null
                if ($quserOutput -and $quserOutput.Count -gt 1) {
                    # Skip the header row and parse each session line
                    foreach ($line in $quserOutput | Select-Object -Skip 1) {
                        $parts = $line -split '\s+' | Where-Object { $_ }
                        if ($parts.Count -gt 0) {
                            # Active sessions are prefixed with '>' — strip it
                            $username = $parts[0].TrimStart('>')
                            $loggedInUsers += [PSCustomObject]@{
                                UserName     = $username
                                ComputerName = $ComputerName
                                Source       = 'QUser'
                            }
                        }
                    }
                }
            }
            catch {
                # Both WMI and quser failed — return empty array
            }
        }

        return $loggedInUsers
    }
    catch {
        throw "Error getting logged-in users: $_"
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-UserDetails, Get-LoggedInUsers
