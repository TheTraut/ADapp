#Requires -Version 5.1
<#
.SYNOPSIS
    Locked accounts management module for ADapp.
.DESCRIPTION
    Provides functions for retrieving locked-out AD users, unlocking accounts,
    validating password complexity, and resetting passwords.
.NOTES
    Module: LockedAccounts
    Author: ADapp Team
    Requires: ActiveDirectory module
#>

#region Functions

function Get-LockedADAccounts {
    <#
    .SYNOPSIS
        Gets all locked-out AD accounts.
    .DESCRIPTION
        Queries Active Directory for all currently locked-out user accounts and
        returns them with extended properties useful for troubleshooting lockouts.
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser[]
        An array of AD user objects with properties including SamAccountName,
        GivenName, Surname, Title, Department, EmailAddress, telephoneNumber,
        CanonicalName, MemberOf, LastLogon, PasswordLastSet, whenChanged,
        lockoutTime, and LastBadPasswordAttempt.
    .EXAMPLE
        Get-LockedADAccounts
    .EXAMPLE
        Get-LockedADAccounts | Select-Object SamAccountName, lockoutTime
    #>
    [CmdletBinding()]
    param ()

    try {
        $lockedUsers = Search-ADAccount -LockedOut |
            Get-ADUser -Properties SamAccountName, GivenName, Surname, Title,
                Department, EmailAddress, telephoneNumber, CanonicalName,
                MemberOf, LastLogon, PasswordLastSet, whenChanged,
                lockoutTime, LastBadPasswordAttempt

        return $lockedUsers
    }
    catch {
        throw "Error getting locked accounts: $_"
    }
}

function Unlock-ADUserAccount {
    <#
    .SYNOPSIS
        Unlocks one or more AD user accounts.
    .DESCRIPTION
        Accepts one or more usernames via parameter or pipeline and attempts to
        unlock each account. Returns a result object per identity indicating
        success or failure.
    .PARAMETER Identity
        The username(s) to unlock. Accepts SamAccountName values from the
        pipeline or by property name.
    .OUTPUTS
        PSCustomObject[]
        Objects with Identity (string), Unlocked (bool), and Error (string)
        properties.
    .EXAMPLE
        Unlock-ADUserAccount -Identity "jsmith"
    .EXAMPLE
        "jsmith", "jdoe" | Unlock-ADUserAccount
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('SamAccountName', 'Username')]
        [string[]]$Identity
    )

    process {
        foreach ($id in $Identity) {
            try {
                Unlock-ADAccount -Identity $id -ErrorAction Stop | Out-Null
                [PSCustomObject]@{ Identity = $id; Unlocked = $true; Error = $null }
            }
            catch {
                [PSCustomObject]@{ Identity = $id; Unlocked = $false; Error = $_.Exception.Message }
            }
        }
    }
}

function Test-PasswordComplexity {
    <#
    .SYNOPSIS
        Validates that a password meets complexity requirements.
    .DESCRIPTION
        Checks the supplied password against the organisation's complexity rules:
        at least 12 characters, one uppercase letter, one lowercase letter, one
        digit, and one special character. Returns a result object with any
        violations listed.
    .PARAMETER Password
        The plain-text password to validate.
    .OUTPUTS
        PSCustomObject
        An object with IsValid (bool) and ErrorMessage (string) properties.
        ErrorMessage is $null when the password passes all checks.
    .EXAMPLE
        Test-PasswordComplexity -Password "MyP@ssw0rd123"
    .EXAMPLE
        $result = Test-PasswordComplexity -Password "weak"
        if (-not $result.IsValid) { Write-Warning $result.ErrorMessage }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $errors = @()

    if ($Password.Length -lt 12) {
        $errors += "Password must be at least 12 characters long"
    }
    if ($Password -cnotmatch '[A-Z]') {
        $errors += "Password must contain at least one uppercase letter"
    }
    if ($Password -cnotmatch '[a-z]') {
        $errors += "Password must contain at least one lowercase letter"
    }
    if ($Password -notmatch '\d') {
        $errors += "Password must contain at least one number"
    }
    if ($Password -notmatch '[!@#$%^&*()_+\-=\[\]{};'':"\\|,.<>\/?]') {
        $errors += "Password must contain at least one special character"
    }

    return [PSCustomObject]@{
        IsValid      = ($errors.Count -eq 0)
        ErrorMessage = if ($errors.Count -gt 0) { $errors -join "`n" } else { $null }
    }
}

function Reset-ADUserPassword {
    <#
    .SYNOPSIS
        Resets an AD user's password.
    .DESCRIPTION
        Validates the new password against complexity requirements, then resets
        the AD account password. Optionally forces the user to change the
        password at next logon.
    .PARAMETER Identity
        The SamAccountName of the user whose password should be reset.
    .PARAMETER NewPassword
        The new password in plain text. It will be converted to a SecureString
        before being sent to AD.
    .PARAMETER ChangeAtLogon
        When specified, the user must change their password at next logon.
    .OUTPUTS
        PSCustomObject
        An object with Identity (string), Success (bool), and Error (string)
        properties.
    .EXAMPLE
        Reset-ADUserPassword -Identity "jsmith" -NewPassword "N3wP@ssw0rd!" -ChangeAtLogon
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$NewPassword,

        [switch]$ChangeAtLogon
    )

    try {
        # Validate complexity before attempting the reset
        $validation = Test-PasswordComplexity -Password $NewPassword
        if (-not $validation.IsValid) {
            return [PSCustomObject]@{
                Identity = $Identity
                Success  = $false
                Error    = $validation.ErrorMessage
            }
        }

        $securePassword = ConvertTo-SecureString -String $NewPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $Identity -NewPassword $securePassword -Reset -ErrorAction Stop

        if ($ChangeAtLogon) {
            Set-ADUser -Identity $Identity -ChangePasswordAtLogon $true -ErrorAction Stop
        }

        return [PSCustomObject]@{
            Identity = $Identity
            Success  = $true
            Error    = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Identity = $Identity
            Success  = $false
            Error    = $_.Exception.Message
        }
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-LockedADAccounts, Unlock-ADUserAccount, Test-PasswordComplexity, Reset-ADUserPassword
