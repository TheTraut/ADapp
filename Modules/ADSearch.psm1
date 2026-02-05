#Requires -Version 5.1

<#
.SYNOPSIS
    ADSearch module for Active Directory object discovery and search operations.
.DESCRIPTION
    Provides functions to search for users, computers, groups, and printers in
    Active Directory.  Includes caching, preferred domain-controller failover,
    DHCP lease resolution, LDAP filter sanitisation, and location-aware filtering.
.NOTES
    Module : ADSearch
    Author : ADapp Team
#>

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "Active Directory module loaded successfully"

    # Import UserLocationIndex module for Test-ComputerOnline function
    Import-Module "$PSScriptRoot\UserLocationIndex.psm1" -ErrorAction Stop
    Write-Verbose "UserLocationIndex module loaded successfully"
}
catch {
    Write-Warning "Failed to load ActiveDirectory module: $_"

    # Provide stub functions so the module can still be loaded without AD
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        function Get-ADUser {
            param([Parameter(Mandatory=$false)][string]$Identity, [Parameter(Mandatory=$false)][string]$Filter, [Parameter(Mandatory=$false)][string[]]$Properties)
            Write-Warning "ActiveDirectory module not available. Get-ADUser stub called."
            return $null
        }

        function Get-ADGroup {
            param([Parameter(Mandatory=$false)][string]$Identity, [Parameter(Mandatory=$false)][string]$Filter, [Parameter(Mandatory=$false)][string[]]$Properties)
            Write-Warning "ActiveDirectory module not available. Get-ADGroup stub called."
            return $null
        }

        function Get-ADComputer {
            param([Parameter(Mandatory=$false)][string]$Identity, [Parameter(Mandatory=$false)][string]$Filter, [Parameter(Mandatory=$false)][string[]]$Properties)
            Write-Warning "ActiveDirectory module not available. Get-ADComputer stub called."
            return $null
        }

        function Get-ADObject {
            <#
            .SYNOPSIS
                Stub for Get-ADObject when the ActiveDirectory module is unavailable.
            .DESCRIPTION
                Returns $null and emits a warning.  Allows the rest of the module to
                load without errors when AD cmdlets are not present.
            .PARAMETER Identity
                The distinguished name or GUID of the AD object.
            .PARAMETER Filter
                An LDAP filter string.
            .PARAMETER Properties
                Additional properties to retrieve.
            .OUTPUTS
                $null
            .EXAMPLE
                Get-ADObject -Filter *
            #>
            param([Parameter(Mandatory=$false)][string]$Identity, [Parameter(Mandatory=$false)][string]$Filter, [Parameter(Mandatory=$false)][string[]]$Properties)
            Write-Warning "ActiveDirectory module not available. Get-ADObject stub called."
            return $null
        }

        function Get-ADOrganizationalUnit {
            <#
            .SYNOPSIS
                Stub for Get-ADOrganizationalUnit when the ActiveDirectory module is unavailable.
            .DESCRIPTION
                Returns $null and emits a warning.  Allows the rest of the module to
                load without errors when AD cmdlets are not present.
            .PARAMETER Identity
                The distinguished name or GUID of the OU.
            .PARAMETER Filter
                An LDAP filter string.
            .PARAMETER Properties
                Additional properties to retrieve.
            .OUTPUTS
                $null
            .EXAMPLE
                Get-ADOrganizationalUnit -Filter *
            #>
            param([Parameter(Mandatory=$false)][string]$Identity, [Parameter(Mandatory=$false)][string]$Filter, [Parameter(Mandatory=$false)][string[]]$Properties)
            Write-Warning "ActiveDirectory module not available. Get-ADOrganizationalUnit stub called."
            return $null
        }
    }
}

# All functions below will work with either real AD cmdlets or our stubs

#region Functions

function Get-PreferredDomainControllers {
    <#
    .SYNOPSIS
        Returns the ordered list of preferred domain controllers.
    .DESCRIPTION
        Reads PreferredDomainControllers from $global:Settings.AD when available,
        otherwise returns an empty list and logs a warning.
    .OUTPUTS
        System.String[]. Ordered array of domain controller hostnames.
    .EXAMPLE
        $dcs = Get-PreferredDomainControllers
    #>
    [CmdletBinding()]
    param()

    try {
        $list = @()
        if ($global:Settings -and $global:Settings.AD -and $global:Settings.AD.PreferredDomainControllers) {
            foreach ($dc in $global:Settings.AD.PreferredDomainControllers) {
                if (-not [string]::IsNullOrWhiteSpace([string]$dc)) {
                    $list += [string]$dc
                }
            }
        }
        if ($list.Count -gt 0) {
            return $list
        }
        try { Write-Log -Message "No domain controllers configured. Set AD.PreferredDomainControllers in settings (e.g. config/settings.json) with your DC FQDNs." -Level "Warning" } catch {}
    }
    catch {
        try { Write-Log -Message "Error reading PreferredDomainControllers from settings: $_" -Level "Warning" } catch {}
    }

    return @()
}

function Get-PreferredDhcpServers {
    <#
    .SYNOPSIS
        Returns the ordered list of DHCP servers to query.
    .DESCRIPTION
        Uses $global:Settings.DHCP.Servers when available; otherwise falls back to
        AD.PreferredDomainControllers. Configure DHCP.Servers or AD.PreferredDomainControllers in settings.
    .OUTPUTS
        System.String[]. Ordered array of DHCP server hostnames.
    .EXAMPLE
        $servers = Get-PreferredDhcpServers
    #>
    [CmdletBinding()]
    param()

    try {
        $list = @()

        # First preference: explicit DHCP servers list in settings
        if ($global:Settings -and $global:Settings.DHCP -and $global:Settings.DHCP.Servers) {
            foreach ($s in $global:Settings.DHCP.Servers) {
                if (-not [string]::IsNullOrWhiteSpace([string]$s)) {
                    $list += [string]$s
                }
            }
        }

        if ($list.Count -eq 0 -and $global:Settings -and $global:Settings.AD -and $global:Settings.AD.PreferredDomainControllers) {
            # Fallback: reuse preferred DCs as DHCP servers
            foreach ($dc in $global:Settings.AD.PreferredDomainControllers) {
                if (-not [string]::IsNullOrWhiteSpace([string]$dc)) {
                    $list += [string]$dc
                }
            }
        }

        if ($list.Count -gt 0) {
            return $list
        }
        try { Write-Log -Message "No DHCP servers configured. Set DHCP.Servers or AD.PreferredDomainControllers in settings." -Level "Warning" } catch {}
    }
    catch {
        try { Write-Log -Message "Error reading DHCP servers from settings: $_" -Level "Warning" } catch {}
    }

    return @()
}

function Resolve-ComputerFromDhcpLease {
    <#
    .SYNOPSIS
        Attempts to resolve a computer name from a DHCP lease by IP address.
    .DESCRIPTION
        Queries each preferred DHCP server for a lease matching the given IPv4
        address and returns the hostname recorded in the lease.
    .PARAMETER IpAddress
        IPv4 address to look up in DHCP.
    .OUTPUTS
        System.String. Computer name (may be FQDN) or $null if not found.
    .EXAMPLE
        Resolve-ComputerFromDhcpLease -IpAddress '10.0.0.50'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    try {
        # Ensure DHCP cmdlets are available
        if (-not (Get-Command Get-DhcpServerv4Lease -ErrorAction SilentlyContinue)) {
            try {
                Import-Module DhcpServer -ErrorAction Stop
            }
            catch {
                try { Write-Log -Message "DhcpServer module not available; skipping DHCP fallback lookup." -Level "Verbose" } catch {}
                return $null
            }
        }
    }
    catch {
        # If we can't even test/load the module, bail out quietly
        return $null
    }

    $servers = Get-PreferredDhcpServers
    foreach ($server in $servers) {
        if ([string]::IsNullOrWhiteSpace($server)) { continue }
        try {
            $lease = Get-DhcpServerv4Lease -ComputerName $server -IPAddress $IpAddress -ErrorAction Stop | Select-Object -First 1
            if ($lease) {
                $hostName = $lease.HostName
                if (-not [string]::IsNullOrWhiteSpace($hostName)) {
                    return [string]$hostName
                }
            }
        }
        catch {
            try {
                Write-Log -Message ("Error querying DHCP server '{0}' for IP {1}: {2}" -f $server, $IpAddress, $_) -Level "Warning"
            } catch {}
        }
    }

    return $null
}

function Convert-OUToCanonical {
    <#
    .SYNOPSIS
        Converts an OU path from distinguished name format to canonical format.
    .DESCRIPTION
        Accepts either canonical (domain.com/Path/OU) or distinguished name
        (OU=...,DC=...) format.  Canonical paths are returned as-is; DN paths
        are resolved via Get-ADOrganizationalUnit.
    .PARAMETER OUPath
        The OU path in either canonical or distinguished name format.
    .OUTPUTS
        System.String. The canonical format of the OU path.
    .EXAMPLE
        Convert-OUToCanonical -OUPath 'OU=Staff,DC=contoso,DC=com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath
    )

    if ([string]::IsNullOrWhiteSpace($OUPath)) {
        return ""
    }

    # Already canonical -- contains a forward-slash separator
    if ($OUPath -match '/') {
        return $OUPath
    }

    # Distinguished name format -- resolve via AD
    try {
        $ou = Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop
        return $ou.CanonicalName
    }
    catch {
        # Conversion failed; return the original value as a best-effort fallback
        Write-Verbose "Could not convert OU path '$OUPath' to canonical format: $_"
        return $OUPath
    }
}

function Get-ADLocations {
    <#
    .SYNOPSIS
        Gets all AD locations (OUs) or filters by base OU.
    .DESCRIPTION
        Returns a sorted, unique list of organizational unit names.  When BaseOU
        is specified only sub-OUs beneath the given base(s) are returned.
    .PARAMETER BaseOU
        Optional base OU(s) to filter by (canonical or distinguished name).
        When specified, only sub-OUs under these bases are returned.
    .OUTPUTS
        System.String[]. Array of OU location names.
    .EXAMPLE
        Get-ADLocations
    .EXAMPLE
        Get-ADLocations -BaseOU 'contoso.com/Sites/HQ'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$BaseOU
    )

    try {
        # Get all organizational units
        $allOUs = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName |
                  Select-Object -ExpandProperty CanonicalName

        $locations = @()

        # If BaseOU is specified, filter to only sub-OUs
        $baseList = @($BaseOU) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        if ($baseList.Count -gt 0) {
            foreach ($base in $baseList) {
                $baseCanonical = Convert-OUToCanonical -OUPath $base
                if ([string]::IsNullOrWhiteSpace($baseCanonical)) {
                    Write-Warning "Could not resolve base OU: $base"
                    continue
                }

                # Extract sub-OUs that are under the base OU
                foreach ($ou in $allOUs) {
                    if ($ou -eq $baseCanonical) {
                        # Skip the base OU itself -- only sub-OUs are wanted
                        continue
                    }
                    if ($ou.StartsWith($baseCanonical + "/")) {
                        # Extract each component of the relative path
                        $relativePath = $ou.Substring($baseCanonical.Length + 1)
                        $parts = $relativePath -split '/'
                        foreach ($part in $parts) {
                            if ($part -and $part.Trim() -ne '' -and $locations -notcontains $part) {
                                $locations += $part
                            }
                        }
                    }
                }
            }
        }
        else {
            # No filter -- extract all location names
            foreach ($ou in $allOUs) {
                $parts = $ou -split '/'
                if ($parts.Count -gt 2) {
                    # Skip the domain name and the domain component
                    for ($i = 2; $i -lt $parts.Count; $i++) {
                        $location = $parts[$i]
                        if ($location -and $location.Trim() -ne '' -and $locations -notcontains $location) {
                            $locations += $location
                        }
                    }
                }
            }
        }

        # Sort and return unique locations
        return $locations | Sort-Object -Unique
    }
    catch {
        Write-Warning "Error retrieving AD locations: $_"
        return @()
    }
}

function Test-ADLocationMatch {
    <#
    .SYNOPSIS
        Tests whether an AD object's canonical location matches a given filter.
    .DESCRIPTION
        Compares a canonical OU path against one or more location filter values.
        Supports full canonical paths, domain-qualified names, and simple OU
        segment names.
    .PARAMETER CurrentLocation
        The canonical name (or DN) of the AD object being tested.
    .PARAMETER LocationFilter
        One or more location filter strings to match against.
    .OUTPUTS
        System.Boolean. $true if the location matches any filter value.
    .EXAMPLE
        Test-ADLocationMatch -CurrentLocation 'contoso.com/Sites/HQ' -LocationFilter 'HQ'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentLocation,

        [Parameter(Mandatory = $true)]
        $LocationFilter
    )

    if ([string]::IsNullOrWhiteSpace($CurrentLocation)) { return $false }

    if ($CurrentLocation -match 'DC=' -and $CurrentLocation -match ',') {
        $converted = Convert-DistinguishedNameToCanonical -DistinguishedName $CurrentLocation
        if (-not [string]::IsNullOrWhiteSpace($converted)) {
            $CurrentLocation = $converted
        }
    }

    $filters = if ($LocationFilter -is [System.Collections.IEnumerable] -and $LocationFilter -isnot [string]) {
        @($LocationFilter)
    }
    else {
        @($LocationFilter)
    }

    foreach ($filter in $filters) {
        if ([string]::IsNullOrWhiteSpace([string]$filter)) { continue }
        $loc = [string]$filter

        # Full canonical path comparison (e.g. domain.com/Sites/HQ)
        if ($loc.Contains(".") -and $loc.Contains("/")) {
            if ($CurrentLocation.Equals($loc, [System.StringComparison]::OrdinalIgnoreCase) -or
                $CurrentLocation.StartsWith($loc + "/", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        elseif ($loc.Contains(".")) {
            if ($CurrentLocation.IndexOf($loc, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
        else {
            # Simple OU name -- match against the path portion after the domain
            $parts = $CurrentLocation -split '/', 2
            if ($parts.Count -lt 2) { continue }
            $ouPath = $parts[1]
            if ($ouPath -eq $loc -or
                $ouPath.StartsWith("$loc/", [System.StringComparison]::OrdinalIgnoreCase) -or
                $ouPath.EndsWith("/$loc", [System.StringComparison]::OrdinalIgnoreCase) -or
                $ouPath.IndexOf("/$loc/", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
    }

    return $false
}

function Convert-DistinguishedNameToCanonical {
    <#
    .SYNOPSIS
        Converts a distinguished name to canonical name format.
    .DESCRIPTION
        Parses a DN string (e.g. OU=Staff,DC=contoso,DC=com) and reconstructs
        it as a canonical path (contoso.com/Staff).  Returns an empty string on
        failure.
    .PARAMETER DistinguishedName
        The full distinguished name to convert.
    .OUTPUTS
        System.String. The canonical representation, or an empty string on error.
    .EXAMPLE
        Convert-DistinguishedNameToCanonical -DistinguishedName 'OU=Staff,DC=contoso,DC=com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    try {
        $parts = $DistinguishedName -split ','
        $ous = New-Object System.Collections.Generic.List[string]
        $dcs = New-Object System.Collections.Generic.List[string]

        foreach ($part in $parts) {
            $trimmed = $part.Trim()
            if ($trimmed -like 'OU=*') {
                $ous.Add($trimmed.Substring(3))
            }
            elseif ($trimmed -like 'DC=*') {
                $dcs.Add($trimmed.Substring(3))
            }
        }

        if ($dcs.Count -eq 0) { return "" }
        $domain = ($dcs -join ".")
        if ($ous.Count -eq 0) { return $domain }

        # OUs are listed innermost-first in a DN, so reverse for canonical order
        $ouPath = [string]::Join("/", [System.Linq.Enumerable]::Reverse($ous))
        return "$domain/$ouPath"
    }
    catch {
        return ""
    }
}

function Sanitize-LdapFilter {
    <#
    .SYNOPSIS
        Escapes special characters in a string for safe use in LDAP filters.
    .DESCRIPTION
        Replaces backslashes, asterisks, parentheses, and other RFC 4515
        special characters with their hex-escaped equivalents.
    .PARAMETER Input
        The raw string to sanitise.
    .OUTPUTS
        System.String. The escaped string safe for LDAP filter insertion.
    .EXAMPLE
        Sanitize-LdapFilter -Input 'O*Brien (test)'
    #>
    [CmdletBinding()]
    param(
        [string]$Input
    )

    if ([string]::IsNullOrEmpty($Input)) { return $Input }
    $s = $Input.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29")
    return $s
}

function Validate-Input {
    <#
    .SYNOPSIS
        Validates that a string is non-null and within a maximum length.
    .DESCRIPTION
        Returns $true when the input is not null and does not exceed MaxLength
        characters; $false otherwise.  Used as a guard before passing user input
        to AD queries.
    .PARAMETER Input
        The string value to validate.
    .PARAMETER MaxLength
        Maximum allowable character count.  Defaults to 256.
    .OUTPUTS
        System.Boolean. $true if the input passes validation.
    .EXAMPLE
        Validate-Input -Input 'jsmith' -MaxLength 256
    #>
    [CmdletBinding()]
    param(
        [string]$Input,

        [int]$MaxLength = 256
    )

    if ($null -eq $Input) { return $false }
    if ($Input.Length -gt $MaxLength) { return $false }
    return $true
}

function Search-ADObjects {
    <#
    .SYNOPSIS
        Searches Active Directory for user and computer objects using a cached approach.
    .DESCRIPTION
        Performs a keyword search against a local cache of AD computer objects
        and/or a live AD query for user objects.  The computer cache is
        automatically refreshed every 15 minutes or on demand with -ForceRefresh.
    .PARAMETER searchTerm
        The search keyword or wildcard pattern.
    .PARAMETER Type
        Object type to search for.  Valid values: All, Computer, User.
        Defaults to All.
    .PARAMETER ForceRefresh
        When specified, forces a refresh of the AD object cache regardless of
        its age.
    .OUTPUTS
        PSCustomObject[]. Array of search result objects with Type, Name,
        Description, and other AD properties.
    .EXAMPLE
        Search-ADObjects -searchTerm 'workstation1'
    .EXAMPLE
        Search-ADObjects -searchTerm 'jsmith' -Type User
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$searchTerm,

        [ValidateSet('All', 'Computer', 'User')]
        [string]$Type = 'All',

        [switch]$ForceRefresh
    )

    try {
        $results = @()

        # Initialise the cache on first use
        if (-not $script:ADObjectCache) {
            $script:ADObjectCache = @{
                Users       = @{}
                Computers   = @{}
                LastRefresh = $null
            }
        }

        # Refresh cache if older than 15 minutes or explicitly requested
        $cacheRefreshNeeded = $ForceRefresh -or
                             (-not $script:ADObjectCache.LastRefresh) -or
                             ((Get-Date) - $script:ADObjectCache.LastRefresh).TotalMinutes -gt 15

        if ($Type -in 'All','Computer') {
            # Refresh computer cache if needed
            if ($cacheRefreshNeeded -and -not $script:ADObjectCache.Computers.Count) {
                Write-Log -Message "Refreshing AD computer cache" -Level "Verbose"

                # Use DirectorySearcher against preferred DCs for bulk retrieval
                $computers = $null
                $preferredDcs = Get-PreferredDomainControllers
                foreach ($dc in $preferredDcs) {
                    try {
                        $root = if ($dc) {
                            New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
                        }
                        else {
                            New-Object System.DirectoryServices.DirectoryEntry
                        }

                        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
                        $searcher.PageSize = 1000
                        $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer))"
                        $searcher.PropertiesToLoad.Add("name") | Out-Null
                        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
                        $searcher.PropertiesToLoad.Add("operatingSystemVersion") | Out-Null
                        $searcher.PropertiesToLoad.Add("description") | Out-Null
                        $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
                        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
                        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
                        $searcher.PropertiesToLoad.Add("memberOf") | Out-Null
                        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

                        $computers = $searcher.FindAll()
                        if ($computers) { break }
                    }
                    catch {
                        try { Write-Log -Message "Error refreshing AD computer cache from DC '$dc': $_" -Level "Warning" } catch {}
                    }
                }

                # Final fallback to default search root if all preferred DCs failed
                if (-not $computers) {
                    try {
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                        $searcher.PageSize = 1000
                        $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer))"
                        $searcher.PropertiesToLoad.Add("name") | Out-Null
                        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
                        $searcher.PropertiesToLoad.Add("operatingSystemVersion") | Out-Null
                        $searcher.PropertiesToLoad.Add("description") | Out-Null
                        $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
                        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
                        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
                        $searcher.PropertiesToLoad.Add("memberOf") | Out-Null
                        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null

                        $computers = $searcher.FindAll()
                    }
                    catch {
                        try { Write-Log -Message "Error refreshing AD computer cache using default search root: $_" -Level "Error" } catch {}
                        $computers = @()
                    }
                }

                # Process each computer and store in cache
                $script:ADObjectCache.Computers = @{}
                foreach ($computer in $computers) {
                    $computerName = if ($computer.Properties["name"].Count -gt 0) { $computer.Properties["name"][0].ToString() } else { "" }
                    if ([string]::IsNullOrEmpty($computerName)) { continue }

                    # Store relevant properties keyed by lower-case name for fast lookup
                    $script:ADObjectCache.Computers[$computerName.ToLower()] = @{
                        Name              = $computerName
                        OperatingSystem   = if ($computer.Properties["operatingSystem"].Count -gt 0) { $computer.Properties["operatingSystem"][0].ToString() } else { "" }
                        OSVersion         = if ($computer.Properties["operatingSystemVersion"].Count -gt 0) { $computer.Properties["operatingSystemVersion"][0].ToString() } else { "" }
                        Description       = if ($computer.Properties["description"].Count -gt 0) { $computer.Properties["description"][0].ToString() } else { "" }
                        LastLogon         = if ($computer.Properties["lastLogonTimestamp"].Count -gt 0) {
                            [datetime]::FromFileTime([Int64]::Parse($computer.Properties["lastLogonTimestamp"][0].ToString()))
                        } else { $null }
                        Enabled           = if ($computer.Properties["userAccountControl"].Count -gt 0) {
                            -not [bool]($computer.Properties["userAccountControl"][0] -band 2)
                        } else { $true }
                        DNSHostName       = if ($computer.Properties["dNSHostName"].Count -gt 0) { $computer.Properties["dNSHostName"][0].ToString() } else { "" }
                        MemberOf          = if ($computer.Properties["memberOf"].Count -gt 0) { $computer.Properties["memberOf"] } else { @() }
                        DistinguishedName = if ($computer.Properties["distinguishedName"].Count -gt 0) { $computer.Properties["distinguishedName"][0].ToString() } else { "" }
                    }
                }

                $script:ADObjectCache.LastRefresh = Get-Date
            }

            # Search in the cache
            $computerResults = $script:ADObjectCache.Computers.Values | Where-Object {
                $_.Name -like "*$searchTerm*"
            }

            foreach ($computer in $computerResults) {
                try {
                    if ([string]::IsNullOrEmpty($computer.Name)) {
                        Write-Warning "Computer object found with no name"
                        continue
                    }

                    # Strip domain suffix to get the NetBIOS-style name
                    $computerName = $computer.Name.Split('.')[0]

                    # Extract CN from each memberOf DN
                    $groups = @()
                    if ($computer.MemberOf) {
                        $groups = $computer.MemberOf | ForEach-Object {
                            if ($_ -match 'CN=([^,]+),') {
                                $matches[1]
                            }
                        }
                    }

                    # Check if computer is online
                    $isOnline = $false
                    try {
                        $isOnline = Test-ComputerOnline -ComputerName $computerName
                    }
                    catch {
                        # Online check is best-effort
                    }

                    $results += [PSCustomObject]@{
                        Type            = 'Computer'
                        Name            = $computerName
                        ObjectType      = 'Computer'
                        Description     = $computer.Description
                        OperatingSystem = $computer.OperatingSystem
                        OSVersion       = $computer.OSVersion
                        Enabled         = $computer.Enabled
                        Status          = $isOnline
                        LastLogon       = if($computer.LastLogon) { $computer.LastLogon.ToString('g') } else { 'Never' }
                        PasswordLastSet = if($computer.PasswordLastSet) { $computer.PasswordLastSet.ToString('g') } else { 'Never' }
                        DNSHostName     = $computer.DNSHostName
                        IPv4Address     = ""
                        OUPath          = $computer.DistinguishedName
                        Groups          = $groups
                        IsOnline        = $isOnline
                    }
                }
                catch {
                    Write-Warning "Error processing computer $($computer.Name): $_"
                }
            }
        }

        # User search
        if ($Type -in 'All','User') {
            # Build user filter
            $safeSearchTerm = $searchTerm
            try {
                if ($global:Settings -and $global:Settings.Security -and $global:Settings.Security.ValidateInputs) {
                    if (-not (Validate-Input -Input $searchTerm)) { throw "Search term too long or invalid." }
                    $safeSearchTerm = Sanitize-LdapFilter -Input $searchTerm
                }
            } catch {}

            if ($safeSearchTerm -eq '*') {
                $userFilter = "SamAccountName -like '*'"
            }
            elseif ($ExactMatch) {
                $userFilter = "SamAccountName -eq '$safeSearchTerm' -or Name -eq '$safeSearchTerm' -or DisplayName -eq '$safeSearchTerm' -or UserPrincipalName -eq '$safeSearchTerm'"
            }
            else {
                # Split search term into potential first and last name parts
                $nameParts = $safeSearchTerm -split '\s+', 2
                $firstName = $nameParts[0]
                $lastName = if ($nameParts.Count -gt 1) { $nameParts[1] } else { $null }

                # Build filter based on whether we have one or two name parts
                if ($lastName) {
                    # Two name parts -- search in both first/last and last/first order
                    $userFilter = "(GivenName -like '*$firstName*' -and Surname -like '*$lastName*') -or " +
                                 "(Surname -like '*$firstName*' -and GivenName -like '*$lastName*') -or " +
                                 "SamAccountName -like '*$safeSearchTerm*' -or " +
                                 "Name -like '*$safeSearchTerm*' -or " +
                                 "DisplayName -like '*$safeSearchTerm*' -or " +
                                 "UserPrincipalName -like '*$safeSearchTerm*'"
                }
                else {
                    # Single part -- search across all name fields
                    $userFilter = "GivenName -like '*$safeSearchTerm*' -or " +
                                 "Surname -like '*$safeSearchTerm*' -or " +
                                 "SamAccountName -like '*$safeSearchTerm*' -or " +
                                 "Name -like '*$safeSearchTerm*' -or " +
                                 "DisplayName -like '*$safeSearchTerm*' -or " +
                                 "UserPrincipalName -like '*$safeSearchTerm*'"
                }
            }

            # Add status filter
            if ($Status -eq 'Enabled') {
                $userFilter = "($userFilter) -and (Enabled -eq `$true)"
            }
            elseif ($Status -eq 'Disabled') {
                $userFilter = "($userFilter) -and (Enabled -eq `$false)"
            }

            # Get all user properties
            $users = Get-ADUser -Filter $userFilter -Properties Enabled, LastLogon, PasswordLastSet, EmailAddress, GivenName, Surname, Title, Department, CanonicalName, telephoneNumber, MemberOf, LockedOut, WhenCreated

            foreach ($user in $users) {
                try {
                    # Apply date filter if specified
                    if ($DateRange -eq "Custom range..." -and $CustomDateStart -and $CustomDateEnd) {
                        if ($user.WhenCreated -lt $CustomDateStart -or $user.WhenCreated -gt $CustomDateEnd) {
                            continue
                        }
                    }
                    elseif ($dateFilter -and $user.WhenCreated -lt $dateFilter) {
                        continue
                    }

                    # Apply location filter if specified
                    if ($Location -and $Location -ne "All Locations") {
                        $currentLocation = $user.CanonicalName
                        if (-not (Test-ADLocationMatch -CurrentLocation $currentLocation -LocationFilter $Location)) {
                            continue
                        }
                    }

                    # Apply inactive filter unless specifically included
                    if (-not $IncludeInactive -and -not $user.Enabled) {
                        continue
                    }

                    # Get group memberships
                    $groups = $user.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }

                    $results += [PSCustomObject]@{
                        Type            = 'User'
                        Name            = $user.SamAccountName
                        ObjectType      = 'User'
                        Description     = "$( $user.GivenName ) $( $user.Surname )"
                        FullName        = "$( $user.GivenName ) $( $user.Surname )"
                        Title           = $user.Title
                        Department      = $user.Department
                        Phone           = $user.telephoneNumber
                        Email           = $user.EmailAddress
                        Enabled         = $user.Enabled
                        LockedOut       = $user.LockedOut
                        LastLogon       = if($user.LastLogon) { [datetime]::FromFileTime($user.LastLogon).ToString('g') } else { 'Never' }
                        PasswordLastSet = if($user.PasswordLastSet) { $user.PasswordLastSet.ToString('g') } else { 'Never' }
                        OUPath          = $user.CanonicalName
                        Groups          = $groups
                    }
                }
                catch {
                    Write-Warning "Error processing user $($user.SamAccountName): $_"
                }
            }
        }

        return $results
    }
    catch {
        Write-Warning "Error in advanced AD search: $_"
        throw
    }
}

function Search-ADObjectsAdvanced {
    <#
    .SYNOPSIS
        Performs an advanced, multi-type search of Active Directory objects.
    .DESCRIPTION
        Searches for users, computers, groups, and/or printers with support for
        location filtering, date-range filtering, exact-match mode, status
        filtering, and preferred domain-controller failover.  IP-address search
        terms automatically trigger a DHCP lease fallback for computers.
    .PARAMETER SearchTerm
        The search keyword, wildcard pattern, or IP address.
    .PARAMETER ObjectType
        Object type(s) to include.  Valid values: All, Computer, User, Group,
        Printer.  Defaults to All.
    .PARAMETER Location
        One or more AD location names or canonical paths to restrict results to.
    .PARAMETER Status
        Filter by account status.  Valid values: All, Enabled, Disabled.
    .PARAMETER DateRange
        Pre-defined date-range filter for the WhenCreated attribute.
    .PARAMETER CustomDateStart
        Start date when DateRange is set to 'Custom range...'.
    .PARAMETER CustomDateEnd
        End date when DateRange is set to 'Custom range...'.
    .PARAMETER ExactMatch
        When $true, performs exact string matching instead of wildcard.
    .PARAMETER IncludeInactive
        When $true, includes disabled accounts in results.
    .OUTPUTS
        PSCustomObject[]. Array of search result objects with Type, Name,
        Description, and other AD properties varying by object type.
    .EXAMPLE
        Search-ADObjectsAdvanced -SearchTerm 'jsmith' -ObjectType User
    .EXAMPLE
        Search-ADObjectsAdvanced -SearchTerm '10.0.0.50' -ObjectType Computer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Computer', 'User', 'Group', 'Printer')]
        [string]$ObjectType = 'All',

        [Parameter(Mandatory = $false)]
        [string[]]$Location,

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Enabled', 'Disabled')]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Any time', 'Today', 'This week', 'This month', 'This year', 'Custom range...')]
        [string]$DateRange,

        [Parameter(Mandatory = $false)]
        [DateTime]$CustomDateStart,

        [Parameter(Mandatory = $false)]
        [DateTime]$CustomDateEnd,

        [Parameter(Mandatory = $false)]
        [bool]$ExactMatch = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeInactive = $false
    )

    try {
        Write-Verbose "Performing advanced search with parameters: SearchTerm=$SearchTerm, ObjectType=$ObjectType, Location=$Location, Status=$Status, DateRange=$DateRange, ExactMatch=$ExactMatch, IncludeInactive=$IncludeInactive"

        if ($DateRange -eq "Custom range..." -and $CustomDateStart -and $CustomDateEnd) {
            Write-Verbose "Using custom date range: $CustomDateStart to $CustomDateEnd"
        }

        $results = @()

        # Wildcard '*' implies all objects -- override exact match
        if ($SearchTerm -eq '*') {
            $ExactMatch = $false
        }

        # Calculate date filters based on DateRange parameter
        $dateFilter = $null
        if ($DateRange -ne "Any time") {
            $now = Get-Date
            switch ($DateRange) {
                "Today"      { $dateFilter = $now.AddDays(-1) }
                "This week"  { $dateFilter = $now.AddDays(-7) }
                "This month" { $dateFilter = $now.AddMonths(-1) }
                "This year"  { $dateFilter = $now.AddYears(-1) }
            }
        }

        # ── Group search ──────────────────────────────────────────────
        if ($ObjectType -in 'All','Group') {
            # Build group filter
            if ($SearchTerm -eq '*') {
                $groupFilter = "Name -like '*'"
            }
            elseif ($ExactMatch) {
                $groupFilter = "Name -eq '$SearchTerm' -or SamAccountName -eq '$SearchTerm'"
            }
            else {
                $groupFilter = "Name -like '*$SearchTerm*' -or SamAccountName -like '*$SearchTerm*' -or Description -like '*$SearchTerm*'"
            }

            # Include email attributes for group email resolution
            $groups = Get-ADGroup -Filter $groupFilter -Properties Name, SamAccountName, Description, GroupScope, GroupCategory, WhenCreated, MemberOf, CanonicalName, DistinguishedName, mail, proxyAddresses

            foreach ($group in $groups) {
                try {
                    # Apply date filter if specified
                    if ($DateRange -eq "Custom range..." -and $CustomDateStart -and $CustomDateEnd) {
                        if ($group.WhenCreated -lt $CustomDateStart -or $group.WhenCreated -gt $CustomDateEnd) {
                            continue
                        }
                    }
                    elseif ($dateFilter -and $group.WhenCreated -lt $dateFilter) {
                        continue
                    }

                    # Apply location filter if specified
                    if ($Location -and $Location -ne "All Locations") {
                        $currentLocation = if ($group.CanonicalName) { $group.CanonicalName } else { $group.DistinguishedName }
                        if (-not (Test-ADLocationMatch -CurrentLocation $currentLocation -LocationFilter $Location)) {
                            continue
                        }
                    }

                    # Get parent groups
                    $parentGroups = $group.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }

                    # Resolve group email: prefer 'mail', then primary SMTP proxy address
                    $groupEmail = ''
                    try {
                        if ($group.mail) {
                            $groupEmail = [string]$group.mail
                        }
                        elseif ($group.proxyAddresses) {
                            $p = $group.proxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1
                            if (-not $p) { $p = $group.proxyAddresses | Where-Object { $_ -cmatch '^smtp:' } | Select-Object -First 1 }
                            if ($p) { $groupEmail = ([string]$p -replace '^(SMTP|smtp):', '') }
                        }
                    } catch {}

                    $results += [PSCustomObject]@{
                        Type              = 'Group'
                        Name              = $group.Name
                        ObjectType        = 'Group'
                        Description       = $group.Description
                        Email             = $groupEmail
                        GroupScope        = $group.GroupScope
                        GroupCategory     = $group.GroupCategory
                        GroupType         = $group.GroupCategory
                        SamAccountName    = $group.SamAccountName
                        DistinguishedName = $group.DistinguishedName
                        ParentGroups      = $parentGroups
                        OUPath            = $group.CanonicalName
                    }
                }
                catch {
                    Write-Warning "Error processing group $($group.Name): $_"
                }
            }
        }

        # ── Computer search ───────────────────────────────────────────
        if ($ObjectType -in 'All','Computer') {
            # Build computer filter, with optional IP-aware search
            $ipRegex = '^\d{1,3}(\.\d{1,3}){3}$'
            if ($SearchTerm -eq '*') {
                $computerFilter = "Name -like '*'"
            }
            elseif ($ExactMatch) {
                if ($SearchTerm -match $ipRegex) {
                    $computerFilter = "Name -eq '$SearchTerm' -or IPv4Address -eq '$SearchTerm' -or DNSHostName -eq '$SearchTerm'"
                }
                else {
                    $computerFilter = "Name -eq '$SearchTerm'"
                }
            }
            else {
                if ($SearchTerm -match $ipRegex) {
                    $computerFilter = "(Name -like '*$SearchTerm*' -or IPv4Address -like '*$SearchTerm*' -or DNSHostName -like '*$SearchTerm*')"
                }
                else {
                    $computerFilter = "Name -like '*$SearchTerm*'"
                }
            }

            # Add status filter
            if ($Status -eq 'Enabled') {
                $computerFilter = "($computerFilter) -and (Enabled -eq `$true)"
            }
            elseif ($Status -eq 'Disabled') {
                $computerFilter = "($computerFilter) -and (Enabled -eq `$false)"
            }

            # Query preferred domain controllers first, then fall back
            $computers = @()
            $preferredDcs = Get-PreferredDomainControllers
            foreach ($dc in $preferredDcs) {
                try {
                    $dcComputers = Get-ADComputer -Filter $computerFilter -Server $dc -Properties Name, OperatingSystem, OperatingSystemVersion, Description, LastLogon, Enabled, DNSHostName, IPv4Address, PasswordLastSet, MemberOf, CanonicalName, WhenCreated
                    if ($dcComputers) {
                        $computers = $dcComputers
                        break
                    }
                }
                catch {
                    try { Write-Log -Message "Get-ADComputer failed using DC '$dc': $_" -Level "Warning" } catch {}
                }
            }

            # Final fallback without explicit DC
            if (-not $computers -or $computers.Count -eq 0) {
                try {
                    $computers = Get-ADComputer -Filter $computerFilter -Properties Name, OperatingSystem, OperatingSystemVersion, Description, LastLogon, Enabled, DNSHostName, IPv4Address, PasswordLastSet, MemberOf, CanonicalName, WhenCreated
                }
                catch {
                    try { Write-Log -Message "Get-ADComputer failed with default server: $_" -Level "Error" } catch {}
                    $computers = @()
                }
            }

            # DHCP fallback: if searching by IP and no AD computer was found, try resolving via DHCP
            if ($SearchTerm -match $ipRegex -and (-not $computers -or $computers.Count -eq 0)) {
                try {
                    $resolvedName = Resolve-ComputerFromDhcpLease -IpAddress $SearchTerm
                    if ($resolvedName) {
                        $shortName = $resolvedName.Split('.')[0]
                        $computers = @()
                        $preferredDcs = Get-PreferredDomainControllers
                        foreach ($dc in $preferredDcs) {
                            try {
                                $dcComputer = Get-ADComputer -Identity $shortName -Server $dc -Properties Name, OperatingSystem, OperatingSystemVersion, Description, LastLogon, Enabled, DNSHostName, IPv4Address, PasswordLastSet, MemberOf, CanonicalName, WhenCreated
                                if ($dcComputer) {
                                    $computers = @($dcComputer)
                                    break
                                }
                            }
                            catch {
                                try { Write-Log -Message "Get-ADComputer (DHCP fallback) failed using DC '$dc': $_" -Level "Warning" } catch {}
                            }
                        }

                        if (-not $computers -or $computers.Count -eq 0) {
                            try {
                                $dcComputer = Get-ADComputer -Identity $shortName -Properties Name, OperatingSystem, OperatingSystemVersion, Description, LastLogon, Enabled, DNSHostName, IPv4Address, PasswordLastSet, MemberOf, CanonicalName, WhenCreated
                                if ($dcComputer) {
                                    $computers = @($dcComputer)
                                }
                            }
                            catch {
                                try { Write-Log -Message "Get-ADComputer (DHCP fallback) failed with default server: $_" -Level "Error" } catch {}
                                $computers = @()
                            }
                        }
                    }
                }
                catch {
                    try {
                        Write-Log -Message ("Error during DHCP fallback lookup for IP {0}: {1}" -f $SearchTerm, $_) -Level "Warning"
                    } catch {}
                }
            }

            foreach ($computer in $computers) {
                try {
                    if ([string]::IsNullOrEmpty($computer.Name)) {
                        Write-Warning "Computer object found with no name"
                        continue
                    }

                    # Apply date filter if specified
                    if ($DateRange -eq "Custom range..." -and $CustomDateStart -and $CustomDateEnd) {
                        if ($computer.WhenCreated -lt $CustomDateStart -or $computer.WhenCreated -gt $CustomDateEnd) {
                            continue
                        }
                    }
                    elseif ($dateFilter -and $computer.WhenCreated -lt $dateFilter) {
                        continue
                    }

                    # Apply location filter if specified
                    if ($Location -and $Location -ne "All Locations") {
                        $currentLocation = if ($computer.CanonicalName) { $computer.CanonicalName } else { $computer.DistinguishedName }
                        if (-not (Test-ADLocationMatch -CurrentLocation $currentLocation -LocationFilter $Location)) {
                            continue
                        }
                    }

                    # Apply inactive filter unless specifically included
                    if (-not $IncludeInactive -and -not $computer.Enabled) {
                        continue
                    }

                    # Strip domain suffix to get the NetBIOS-style name
                    $computerName = $computer.Name.Split('.')[0]

                    # Get group memberships
                    $groups = $computer.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }

                    # Check if computer is online
                    $isOnline = $false
                    try {
                        $isOnline = Test-ComputerOnline -ComputerName $computerName
                    }
                    catch {
                        # Online check is best-effort
                    }

                    # Choose a single IPv4 address if multiple are present
                    $ipv4 = ""
                    try {
                        $rawIp = $computer.IPv4Address
                        if ($rawIp) {
                            if ($rawIp -is [System.Array]) {
                                $ipv4 = ($rawIp | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Last 1)
                            }
                            else {
                                $ipv4 = [string]$rawIp
                            }
                        }
                    }
                    catch {
                        $ipv4 = ""
                    }

                    $results += [PSCustomObject]@{
                        Type            = 'Computer'
                        Name            = $computerName
                        ObjectType      = 'Computer'
                        Description     = $computer.Description
                        OperatingSystem = $computer.OperatingSystem
                        OSVersion       = $computer.OperatingSystemVersion
                        Enabled         = $computer.Enabled
                        Status          = $isOnline
                        LastLogon       = if($computer.LastLogon) { [datetime]::FromFileTime($computer.LastLogon).ToString('g') } else { 'Never' }
                        PasswordLastSet = if($computer.PasswordLastSet) { $computer.PasswordLastSet.ToString('g') } else { 'Never' }
                        DNSHostName     = $computer.DNSHostName
                        IPv4Address     = $ipv4
                        OUPath          = $computer.CanonicalName
                        Groups          = $groups
                        IsOnline        = $isOnline
                    }
                }
                catch {
                    Write-Warning "Error processing computer $($computer.Name): $_"
                }
            }
        }

        # ── User search ───────────────────────────────────────────────
        if ($ObjectType -in 'All','User') {
            # Build user filter
            if ($SearchTerm -eq '*') {
                $userFilter = "SamAccountName -like '*'"
            }
            elseif ($ExactMatch) {
                $userFilter = "SamAccountName -eq '$SearchTerm' -or Name -eq '$SearchTerm' -or DisplayName -eq '$SearchTerm' -or UserPrincipalName -eq '$SearchTerm'"
            }
            else {
                # Split search term into potential first and last name parts
                $nameParts = $SearchTerm -split '\s+', 2
                $firstName = $nameParts[0]
                $lastName = if ($nameParts.Count -gt 1) { $nameParts[1] } else { $null }

                # Build filter based on whether we have one or two name parts
                if ($lastName) {
                    # Two name parts -- search in both first/last and last/first order
                    $userFilter = "(GivenName -like '*$firstName*' -and Surname -like '*$lastName*') -or " +
                                 "(Surname -like '*$firstName*' -and GivenName -like '*$lastName*') -or " +
                                 "SamAccountName -like '*$SearchTerm*' -or " +
                                 "Name -like '*$SearchTerm*' -or " +
                                 "DisplayName -like '*$SearchTerm*' -or " +
                                 "UserPrincipalName -like '*$SearchTerm*'"
                }
                else {
                    # Single part -- search across all name fields
                    $userFilter = "GivenName -like '*$SearchTerm*' -or " +
                                 "Surname -like '*$SearchTerm*' -or " +
                                 "SamAccountName -like '*$SearchTerm*' -or " +
                                 "Name -like '*$SearchTerm*' -or " +
                                 "DisplayName -like '*$SearchTerm*' -or " +
                                 "UserPrincipalName -like '*$SearchTerm*'"
                }
            }

            # Add status filter
            if ($Status -eq 'Enabled') {
                $userFilter = "($userFilter) -and (Enabled -eq `$true)"
            }
            elseif ($Status -eq 'Disabled') {
                $userFilter = "($userFilter) -and (Enabled -eq `$false)"
            }

            # Get all user properties
            $users = Get-ADUser -Filter $userFilter -Properties Enabled, LastLogon, PasswordLastSet, EmailAddress, GivenName, Surname, Title, Department, CanonicalName, telephoneNumber, MemberOf, LockedOut, WhenCreated

            foreach ($user in $users) {
                try {
                    # Apply date filter if specified
                    if ($DateRange -eq "Custom range..." -and $CustomDateStart -and $CustomDateEnd) {
                        if ($user.WhenCreated -lt $CustomDateStart -or $user.WhenCreated -gt $CustomDateEnd) {
                            continue
                        }
                    }
                    elseif ($dateFilter -and $user.WhenCreated -lt $dateFilter) {
                        continue
                    }

                    # Apply location filter if specified
                    if ($Location -and $Location -ne "All Locations") {
                        $currentLocation = if ($user.CanonicalName) { $user.CanonicalName } else { $user.DistinguishedName }
                        if (-not (Test-ADLocationMatch -CurrentLocation $currentLocation -LocationFilter $Location)) {
                            continue
                        }
                    }

                    # Apply inactive filter unless specifically included
                    if (-not $IncludeInactive -and -not $user.Enabled) {
                        continue
                    }

                    # Get group memberships
                    $groups = $user.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }

                    $results += [PSCustomObject]@{
                        Type            = 'User'
                        Name            = $user.SamAccountName
                        ObjectType      = 'User'
                        Description     = "$($user.GivenName) $($user.Surname)"
                        FullName        = "$($user.GivenName) $($user.Surname)"
                        Title           = $user.Title
                        Department      = $user.Department
                        Phone           = $user.telephoneNumber
                        Email           = $user.EmailAddress
                        Enabled         = $user.Enabled
                        LockedOut       = $user.LockedOut
                        LastLogon       = if($user.LastLogon) { [datetime]::FromFileTime($user.LastLogon).ToString('g') } else { 'Never' }
                        PasswordLastSet = if($user.PasswordLastSet) { $user.PasswordLastSet.ToString('g') } else { 'Never' }
                        OUPath          = $user.CanonicalName
                        Groups          = $groups
                    }
                }
                catch {
                    Write-Warning "Error processing user $($user.SamAccountName): $_"
                }
            }
        }

        # ── Printer search ────────────────────────────────────────────
        if ($ObjectType -in 'All','Printer') {
            # Get print server from settings
            $printServer = ""
            if ($global:Settings -and $global:Settings.Printers -and $global:Settings.Printers.PrintServer) {
                $printServer = $global:Settings.Printers.PrintServer.Trim()
            }

            if ([string]::IsNullOrWhiteSpace($printServer)) {
                Write-Log -Message "Print server not configured in settings. Skipping printer search." -Level "Warning"
            }
            else {
                try {
                    # Build candidate list: configured name, then short/FQDN variant
                    $serverCandidates = @()
                    $configuredName = $printServer.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($configuredName)) {
                        $serverCandidates += $configuredName
                        if ($configuredName.Contains('.')) {
                            $serverCandidates += $configuredName.Split('.')[0].Trim()
                        }
                        else {
                            try {
                                $domainFqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                                if ($domainFqdn) { $serverCandidates += "$configuredName.$domainFqdn" }
                            } catch {}
                        }
                    }
                    $addedPrinterCount = 0

                    # Get-Printer requires Windows Server 2012+ / Windows 10+
                    if (-not (Get-Command Get-Printer -ErrorAction SilentlyContinue)) {
                        Write-Log -Message "Get-Printer cmdlet not available. Printer search requires Windows Server 2012+ or Windows 10+." -Level "Warning"
                    }
                    else {
                        foreach ($candidate in $serverCandidates) {
                            try {
                                Write-Verbose "Searching printers on print server: $candidate"
                                $printers = Get-Printer -ComputerName $candidate -ErrorAction Stop

                                foreach ($printer in $printers) {
                                    try {
                                        if ([string]::IsNullOrEmpty($printer.Name)) { continue }

                                        # Apply search filter across Name, ShareName, Comment, Location
                                        $matchesSearch = $false
                                        if ($SearchTerm -eq '*') {
                                            $matchesSearch = $true
                                        }
                                        else {
                                            $fields = @($printer.Name, $printer.ShareName, $printer.Comment, $printer.Location) | Where-Object { $_ }
                                            if ($ExactMatch) {
                                                $matchesSearch = ($fields | Where-Object { $_ -eq $SearchTerm }).Count -gt 0
                                            }
                                            else {
                                                $matchesSearch = ($fields | Where-Object { $_ -like "*$SearchTerm*" }).Count -gt 0
                                            }
                                        }
                                        if (-not $matchesSearch) { continue }

                                        # Get share name and port
                                        $shareName   = if ($printer.ShareName) { $printer.ShareName } else { "" }
                                        $portName    = if ($printer.PortName) { $printer.PortName } else { "" }
                                        $description = if ($printer.Description) { $printer.Description } else { "" }

                                        $results += [PSCustomObject]@{
                                            Type        = 'Printer'
                                            Name        = $printer.Name
                                            ObjectType  = 'Printer'
                                            ShareName   = $shareName
                                            Port        = $portName
                                            Description = $description
                                        }
                                        $addedPrinterCount++
                                    }
                                    catch {
                                        Write-Warning "Error processing printer $($printer.Name): $_"
                                    }
                                }

                                if ($addedPrinterCount -gt 0) { break }
                            }
                            catch {
                                Write-Log -Message "Get-Printer failed for '$candidate': $_" -Level "Warning"
                                continue
                            }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error querying printers from print server '$printServer': $_" -Level "Warning"
                }

                # No AD fallback: printers are only returned from the print server query above
            }
        }

        return $results
    }
    catch {
        Write-Warning "Error in advanced AD search: $_"
        throw
    }
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────
Export-ModuleMember -Function Get-ADLocations, Search-ADObjects, Search-ADObjectsAdvanced
