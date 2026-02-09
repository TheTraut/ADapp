#Requires -Version 5.1

<#
.SYNOPSIS
    Security group management module for the ADapp application.
.DESCRIPTION
    Provides functions for querying, adding, and removing Active Directory
    security and distribution group memberships for users and workstations,
    as well as GUI dialogs for interactive group management.
.NOTES
    Module : SecurityGroups
    Author : ADapp Team
#>

#region Functions

function Get-ADSecurityGroups {
    <#
    .SYNOPSIS
        Retrieves all security and distribution groups from Active Directory.
    .DESCRIPTION
        Queries AD for every group object, extracts name, description, scope,
        category, and primary SMTP email address (falling back through
        proxyAddresses when the mail attribute is empty), and returns the
        results sorted by name. Restricted / built-in groups are NOT filtered
        here; callers decide what to exclude.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Each object contains Name, Description, GroupScope, GroupCategory, and Email.
        Returns $null on failure.
    .EXAMPLE
        $groups = Get-ADSecurityGroups
        Retrieves every group from AD with its email address resolved.
    #>
    [CmdletBinding()]
    param()

    try {
        $groups = Get-ADGroup -Filter "*" -Properties Name, Description, GroupScope, GroupCategory, mail, proxyAddresses |
                 Select-Object `
                    Name, `
                    Description, `
                    GroupScope, `
                    GroupCategory, `
                    @{ Name = 'Email'; Expression = {
                        if ($_.mail) { return [string]$_.mail }
                        $p = $null
                        if ($_.proxyAddresses) {
                            # Prefer the primary (upper-case SMTP:) address
                            $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1
                            if (-not $p) { $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^smtp:' } | Select-Object -First 1 }
                        }
                        if ($p) { return ([string]$p -replace '^(SMTP|smtp):', '') }
                        return ''
                    }} |
                 Sort-Object Name

        Write-Log "Retrieved $($groups.Count) groups from AD"
        return $groups
    }
    catch {
        Write-Log "Error retrieving groups: $_" -Warning
        return $null
    }
}

function Add-UserToSecurityGroup {
    <#
    .SYNOPSIS
        Adds an AD user to a security group.
    .DESCRIPTION
        Validates that both the user and group exist in Active Directory, then
        adds the user as a member of the specified group. An audit event is
        recorded on success.
    .PARAMETER Username
        The SamAccountName (or other identity) of the user to add.
    .PARAMETER GroupName
        The identity of the target security group.
    .OUTPUTS
        System.Boolean
        Returns $true on success, $false on failure.
    .EXAMPLE
        Add-UserToSecurityGroup -Username 'jsmith' -GroupName 'VPN-Users'
        Adds jsmith to the VPN-Users security group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    try {
        $user = Get-ADUser -Identity $Username -ErrorAction Stop
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

        Add-ADGroupMember -Identity $group -Members $user -ErrorAction Stop
        try { Write-AuditEvent -Action 'AddGroupMember' -Target "$($group):$($user)" -Result 'Success' } catch {}

        Write-Log "Added user $Username to security group $GroupName successfully"
        return $true
    }
    catch {
        Write-Log "Error adding user to security group: $_" -Warning
        return $false
    }
}

function Remove-UserFromSecurityGroup {
    <#
    .SYNOPSIS
        Removes an AD user from a security group.
    .DESCRIPTION
        Validates that both the user and group exist in Active Directory, then
        removes the user from the specified group without prompting for
        confirmation. An audit event is recorded on success.
    .PARAMETER Username
        The SamAccountName (or other identity) of the user to remove.
    .PARAMETER GroupName
        The identity of the target security group.
    .OUTPUTS
        System.Boolean
        Returns $true on success, $false on failure.
    .EXAMPLE
        Remove-UserFromSecurityGroup -Username 'jsmith' -GroupName 'VPN-Users'
        Removes jsmith from the VPN-Users security group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    try {
        $user = Get-ADUser -Identity $Username -ErrorAction Stop
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

        Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
        try { Write-AuditEvent -Action 'RemoveGroupMember' -Target "$($group):$($user)" -Result 'Success' } catch {}

        Write-Log "Removed user $Username from security group $GroupName successfully"
        return $true
    }
    catch {
        Write-Log "Error removing user from security group: $_" -Warning
        return $false
    }
}

function Add-WorkstationToSecurityGroup {
    <#
    .SYNOPSIS
        Adds an AD computer to a security group.
    .DESCRIPTION
        Strips any FQDN suffix from the computer name, validates that the
        computer and group exist in AD, then adds the computer as a member of
        the group. An audit event is recorded on success.
    .PARAMETER ComputerName
        The name of the computer to add. An FQDN is accepted and will be
        normalised to the short hostname.
    .PARAMETER GroupName
        The identity of the target security group.
    .OUTPUTS
        System.Boolean
        Returns $true on success, $false on failure.
    .EXAMPLE
        Add-WorkstationToSecurityGroup -ComputerName 'WS-PC01' -GroupName 'WSUS-Pilot'
        Adds WS-PC01 to the WSUS-Pilot security group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    try {
        # Strip domain suffix so the identity lookup works with FQDNs
        $ComputerName = $ComputerName.Split('.')[0]

        $computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

        Add-ADGroupMember -Identity $group -Members $computer -ErrorAction Stop
        try { Write-AuditEvent -Action 'AddComputerToGroup' -Target "$($group):$($computer)" -Result 'Success' } catch {}

        Write-Log "Added workstation $ComputerName to security group $GroupName successfully"
        return $true
    }
    catch {
        Write-Log "Error adding workstation to security group: $_" -Warning
        return $false
    }
}

function Remove-WorkstationFromSecurityGroup {
    <#
    .SYNOPSIS
        Removes an AD computer from a security group.
    .DESCRIPTION
        Strips any FQDN suffix from the computer name, validates that the
        computer and group exist in AD, then removes the computer from the
        group without prompting for confirmation. An audit event is recorded
        on success.
    .PARAMETER ComputerName
        The name of the computer to remove. An FQDN is accepted and will be
        normalised to the short hostname.
    .PARAMETER GroupName
        The identity of the target security group.
    .OUTPUTS
        System.Boolean
        Returns $true on success, $false on failure.
    .EXAMPLE
        Remove-WorkstationFromSecurityGroup -ComputerName 'WS-PC01' -GroupName 'WSUS-Pilot'
        Removes WS-PC01 from the WSUS-Pilot security group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    try {
        # Strip domain suffix so the identity lookup works with FQDNs
        $ComputerName = $ComputerName.Split('.')[0]

        $computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

        Remove-ADGroupMember -Identity $group -Members $computer -Confirm:$false -ErrorAction Stop
        try { Write-AuditEvent -Action 'RemoveComputerFromGroup' -Target "$($group):$($computer)" -Result 'Success' } catch {}

        Write-Log "Removed workstation $ComputerName from security group $GroupName successfully"
        return $true
    }
    catch {
        Write-Log "Error removing workstation from security group: $_" -Warning
        return $false
    }
}

function Get-UserSecurityGroups {
    <#
    .SYNOPSIS
        Retrieves the security groups a user belongs to.
    .DESCRIPTION
        Looks up the user's MemberOf attribute, then resolves each group to
        return name, description, scope, category, and primary SMTP email
        address. Results are sorted by name.
    .PARAMETER Username
        The SamAccountName (or other identity) of the user to query.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Each object contains Name, Description, GroupScope, GroupCategory, and Email.
        Returns $null on failure.
    .EXAMPLE
        Get-UserSecurityGroups -Username 'jsmith'
        Lists every group that jsmith is a member of.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        $user = Get-ADUser -Identity $Username -Properties MemberOf -ErrorAction Stop
        $groups = $user.MemberOf | ForEach-Object {
            Get-ADGroup -Identity $_ -Properties Name, Description, GroupScope, GroupCategory, mail, proxyAddresses |
            Select-Object `
                Name, `
                Description, `
                GroupScope, `
                GroupCategory, `
                @{ Name = 'Email'; Expression = {
                    if ($_.mail) { return [string]$_.mail }
                    $p = $null
                    if ($_.proxyAddresses) {
                        # Prefer the primary (upper-case SMTP:) address
                        $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1
                        if (-not $p) { $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^smtp:' } | Select-Object -First 1 }
                    }
                    if ($p) { return ([string]$p -replace '^(SMTP|smtp):', '') }
                    return ''
                }}
        } | Sort-Object Name

        Write-Log "Retrieved $($groups.Count) groups for user $Username"
        return $groups
    }
    catch {
        Write-Log "Error retrieving groups for user: $_" -Warning
        return $null
    }
}

function Get-WorkstationSecurityGroups {
    <#
    .SYNOPSIS
        Retrieves the security groups a workstation belongs to.
    .DESCRIPTION
        Strips any FQDN suffix from the computer name, looks up the
        computer's MemberOf attribute, then resolves each group to return
        name, description, scope, category, and primary SMTP email address.
        Results are sorted by name.
    .PARAMETER ComputerName
        The name of the computer to query. An FQDN is accepted and will be
        normalised to the short hostname.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
        Each object contains Name, Description, GroupScope, GroupCategory, and Email.
        Returns $null on failure.
    .EXAMPLE
        Get-WorkstationSecurityGroups -ComputerName 'WS-PC01'
        Lists every group that WS-PC01 is a member of.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Strip domain suffix so the identity lookup works with FQDNs
        $ComputerName = $ComputerName.Split('.')[0]

        $computer = Get-ADComputer -Identity $ComputerName -Properties MemberOf -ErrorAction Stop
        $groups = $computer.MemberOf | ForEach-Object {
            Get-ADGroup -Identity $_ -Properties Name, Description, GroupScope, GroupCategory, mail, proxyAddresses |
            Select-Object `
                Name, `
                Description, `
                GroupScope, `
                GroupCategory, `
                @{ Name = 'Email'; Expression = {
                    if ($_.mail) { return [string]$_.mail }
                    $p = $null
                    if ($_.proxyAddresses) {
                        # Prefer the primary (upper-case SMTP:) address
                        $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1
                        if (-not $p) { $p = $_.proxyAddresses | Where-Object { $_ -cmatch '^smtp:' } | Select-Object -First 1 }
                    }
                    if ($p) { return ([string]$p -replace '^(SMTP|smtp):', '') }
                    return ''
                }}
        } | Sort-Object Name

        Write-Log "Retrieved $($groups.Count) groups for workstation $ComputerName"
        return $groups
    }
    catch {
        Write-Log "Error retrieving groups for workstation: $_" -Warning
        return $null
    }
}

function Show-GroupManagementDialog {
    <#
    .SYNOPSIS
        Displays a dialog for selecting security groups to add or remove.
    .DESCRIPTION
        Presents a searchable, checkbox-enabled list of all AD groups (with
        restricted built-in groups filtered out). Groups that the target
        object already belongs to are pre-checked. On confirmation the
        function returns a hashtable describing which groups to add and which
        to remove.
    .PARAMETER Title
        The title text shown in the dialog window title bar.
    .PARAMETER CurrentGroups
        An array of group names the target object currently belongs to.
        These groups will be pre-checked in the list.
    .PARAMETER IsComputer
        When $true, indicates the target is a computer object. Defaults to
        $false (user object).
    .OUTPUTS
        System.Collections.Hashtable
        A hashtable with keys 'ToAdd' and 'ToRemove', each containing an
        array of group names. Returns $null if the user cancels.
    .EXAMPLE
        $changes = Show-GroupManagementDialog -Title 'Groups for jsmith' -CurrentGroups @('VPN-Users','Staff')
        Opens the dialog pre-checking VPN-Users and Staff.
    #>
    [CmdletBinding()]
    param(
        [string]$Title,

        [array]$CurrentGroups,

        [bool]$IsComputer = $false
    )

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text              = $Title
    $dialog.Size              = New-Object System.Drawing.Size(780, 500)
    $dialog.StartPosition     = "CenterParent"
    $dialog.FormBorderStyle   = "FixedDialog"
    $dialog.MaximizeBox       = $false
    $dialog.MinimizeBox       = $false

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Location = New-Object System.Drawing.Point(10, 10)
    $searchLabel.Size     = New-Object System.Drawing.Size(100, 20)
    $searchLabel.Text     = "Search Groups:"
    $dialog.Controls.Add($searchLabel)

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(110, 10)
    $searchBox.Size     = New-Object System.Drawing.Size(200, 20)
    $dialog.Controls.Add($searchBox)

    $groupListView = New-Object System.Windows.Forms.ListView
    $groupListView.Location      = New-Object System.Drawing.Point(10, 40)
    $groupListView.Size          = New-Object System.Drawing.Size(745, 350)
    $groupListView.View          = [System.Windows.Forms.View]::Details
    $groupListView.FullRowSelect = $true
    $groupListView.MultiSelect   = $false
    $groupListView.CheckBoxes    = $true

    $null = $groupListView.Columns.Add("Name", 200)
    $null = $groupListView.Columns.Add("Description", 220)
    $null = $groupListView.Columns.Add("Email", 180)
    $null = $groupListView.Columns.Add("Group Type", 100)
    $null = $groupListView.Columns.Add("Scope", 75)

    Add-ListViewSorting -ListView $groupListView

    $dialog.Controls.Add($groupListView)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(10, 400)
    $statusLabel.Size     = New-Object System.Drawing.Size(745, 20)
    $statusLabel.Text     = "Loading groups..."
    $dialog.Controls.Add($statusLabel)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location     = New-Object System.Drawing.Point(580, 430)
    $okButton.Size         = New-Object System.Drawing.Size(75, 23)
    $okButton.Text         = "OK"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton   = $okButton
    $dialog.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location     = New-Object System.Drawing.Point(670, 430)
    $cancelButton.Size         = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text         = "Cancel"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.CancelButton       = $cancelButton
    $dialog.Controls.Add($cancelButton)

    $allGroups = Get-ADSecurityGroups

    # Prevent accidental modification of sensitive built-in groups
    $restrictedGroups = @(
        "Schema Admins", "Key Admins", "Enterprise Admins", "Domain Admins",
        "Administrators", "Hyper-V Administrators", "Domain Controllers",
        "Domain Computers", "Cert Publishers", "Certificate Service DCOM Access",
        "RDS Remote Access Servers", "RDS Endpoint Servers", "RDS Management Servers",
        "Access Control Assistance Operators", "Storage Replica Administrators",
        "RAS and IAS Servers", "Pre-Windows 2000 Compatible Access",
        "Incoming Forest Trust Builders", "Windows Authorization Access Group",
        "Terminal Server License Servers", "Allowed RODC Password Replication Group",
        "Denied RODC Password Replication Group", "Read-only Domain Controllers",
        "Enterprise Read-only Domain Controllers", "Cloneable Domain Controllers",
        "DnsAdmins", "DnsUpdateProxy", "Enterprise Key Admins"
    )

    $allGroups = $allGroups | Where-Object { $restrictedGroups -notcontains $_.Name }

    # Track checked state independently so it survives search/filter refreshes
    $checkedGroups = [System.Collections.ArrayList]::new()
    if ($CurrentGroups) {
        $checkedGroups.AddRange($CurrentGroups)
    }

    $groupListView.Add_ItemChecked({
        $item = $_.Item
        if ($item.Checked) {
            if (-not $checkedGroups.Contains($item.Text)) {
                [void]$checkedGroups.Add($item.Text)
            }
        }
        else {
            if ($checkedGroups.Contains($item.Text)) {
                [void]$checkedGroups.Remove($item.Text)
            }
        }
    })

    # Rebuild the ListView contents based on the current search text
    $updateList = {
        $groupListView.BeginUpdate()
        $groupListView.Items.Clear()
        $searchText = $searchBox.Text.ToLower()

        $filteredGroups = $allGroups
        if ($searchText) {
            $filteredGroups = $allGroups | Where-Object {
                $_.Name.ToLower().Contains($searchText) -or
                ($_.Description -and $_.Description.ToLower().Contains($searchText)) -or
                ($_.Email -and $_.Email.ToLower().Contains($searchText))
            }
        }

        foreach ($group in $filteredGroups) {
            try {
                $item = New-Object System.Windows.Forms.ListViewItem($group.Name)
                $item.SubItems.Add($(if ($group.Description) { $group.Description } else { "" }))
                $item.SubItems.Add($(if ($group.PSObject.Properties.Match('Email').Count -gt 0 -and $group.Email) { $group.Email } else { "" }))
                $item.SubItems.Add($group.GroupCategory.ToString())
                $item.SubItems.Add($group.GroupScope.ToString())
                $item.Tag = $group

                if ($checkedGroups.Contains($group.Name)) {
                    $item.Checked = $true
                }

                [void]$groupListView.Items.Add($item)
            }
            catch {
                Write-Log "Error adding group to list: $($group.Name) - $_" -Warning
                continue
            }
        }

        $statusLabel.Text = "Found $($filteredGroups.Count) groups"
        $groupListView.EndUpdate()
    }

    $searchBox.Add_TextChanged({
        & $updateList
    })

    # Initial population
    & $updateList

    $result = $dialog.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Diff current vs. checked to determine what changed
        return @{
            ToAdd    = $checkedGroups | Where-Object { $CurrentGroups -notcontains $_ }
            ToRemove = $CurrentGroups | Where-Object { $checkedGroups -notcontains $_ }
        }
    }

    return $null
}

function Show-GroupMembersDialog {
    <#
    .SYNOPSIS
        Displays a dialog for managing the members of a single security group.
    .DESCRIPTION
        Presents the current members of the specified group in a searchable,
        checkbox-enabled list. Members can be unchecked to remove them or new
        members can be added via a nested search dialog. Changes are applied
        to AD when the user clicks OK.
    .PARAMETER GroupName
        The identity of the group whose members are managed.
    .PARAMETER Title
        The title text shown in the dialog window title bar. Defaults to
        'Manage Group Members'.
    .OUTPUTS
        System.Boolean
        Returns $true if the user confirmed changes, $false if cancelled.
    .EXAMPLE
        Show-GroupMembersDialog -GroupName 'VPN-Users'
        Opens the member-management dialog for the VPN-Users group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [string]$Title = "Manage Group Members"
    )

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text            = "$Title - $GroupName"
    $dialog.Size            = New-Object System.Drawing.Size(800, 600)
    $dialog.StartPosition   = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox     = $false
    $dialog.MinimizeBox     = $false

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Location = New-Object System.Drawing.Point(10, 10)
    $searchLabel.Size     = New-Object System.Drawing.Size(100, 20)
    $searchLabel.Text     = "Search Members:"
    $dialog.Controls.Add($searchLabel)

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(110, 10)
    $searchBox.Size     = New-Object System.Drawing.Size(200, 20)
    $dialog.Controls.Add($searchBox)

    $membersListView = New-Object System.Windows.Forms.ListView
    $membersListView.Location      = New-Object System.Drawing.Point(10, 40)
    $membersListView.Size          = New-Object System.Drawing.Size(765, 450)
    $membersListView.View          = [System.Windows.Forms.View]::Details
    $membersListView.FullRowSelect = $true
    $membersListView.MultiSelect   = $true
    $membersListView.CheckBoxes    = $true

    $null = $membersListView.Columns.Add("Name", 200)
    $null = $membersListView.Columns.Add("Type", 100)
    $null = $membersListView.Columns.Add("Distinguished Name", 400)

    Add-ListViewSorting -ListView $membersListView

    $dialog.Controls.Add($membersListView)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(10, 500)
    $statusLabel.Size     = New-Object System.Drawing.Size(765, 20)
    $statusLabel.Text     = "Loading members..."
    $dialog.Controls.Add($statusLabel)

    $addButton = New-Object System.Windows.Forms.Button
    $addButton.Location = New-Object System.Drawing.Point(610, 530)
    $addButton.Size     = New-Object System.Drawing.Size(75, 23)
    $addButton.Text     = "Add..."
    $dialog.Controls.Add($addButton)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location     = New-Object System.Drawing.Point(700, 530)
    $okButton.Size         = New-Object System.Drawing.Size(75, 23)
    $okButton.Text         = "OK"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton   = $okButton
    $dialog.Controls.Add($okButton)

    # Resolve group identity via DN for reliable lookups
    $groupIdentity = $GroupName
    try {
        try { $grp = Get-ADGroup -Identity $GroupName -ErrorAction Stop } catch { $grp = $null }
        if (-not $grp) { try { $grp = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'" -ErrorAction Stop } catch { $grp = $null } }
        if (-not $grp) { try { $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction Stop } catch { $grp = $null } }
        if ($grp -and $grp.DistinguishedName) { $groupIdentity = $grp.DistinguishedName }
    } catch {}

    # Keep a reference to original members so the search filter can rebuild the list
    $originalMembers = @{}

    $loadMembers = {
        $membersListView.BeginUpdate()
        $membersListView.Items.Clear()

        try {
            $members = Get-ADGroupMember -Identity $groupIdentity | Get-ADObject -Properties Name, ObjectClass, DistinguishedName

            foreach ($member in $members) {
                $item = New-Object System.Windows.Forms.ListViewItem($member.Name)
                $item.SubItems.Add($member.ObjectClass)
                $item.SubItems.Add($member.DistinguishedName)
                $item.Tag     = $member
                $item.Checked = $true
                [void]$membersListView.Items.Add($item)
                $originalMembers[$member.DistinguishedName] = $member
            }

            $statusLabel.Text = "Found $($members.Count) members"
        }
        catch {
            $statusLabel.Text = "Error loading members: $_"
        }
        finally {
            $membersListView.EndUpdate()
        }
    }

    # Rebuild the ListView contents based on the current search text
    $updateList = {
        $membersListView.BeginUpdate()
        $searchText = $searchBox.Text.ToLower()

        if ($searchText) {
            $membersListView.Items.Clear()
            foreach ($member in $originalMembers.Values) {
                if ($member.Name.ToLower().Contains($searchText)) {
                    $item = New-Object System.Windows.Forms.ListViewItem($member.Name)
                    $item.SubItems.Add($member.ObjectClass)
                    $item.SubItems.Add($member.DistinguishedName)
                    $item.Tag     = $member
                    $item.Checked = $true
                    [void]$membersListView.Items.Add($item)
                }
            }
        }
        else {
            $membersListView.Items.Clear()
            foreach ($member in $originalMembers.Values) {
                $item = New-Object System.Windows.Forms.ListViewItem($member.Name)
                $item.SubItems.Add($member.ObjectClass)
                $item.SubItems.Add($member.DistinguishedName)
                $item.Tag     = $member
                $item.Checked = $true
                [void]$membersListView.Items.Add($item)
            }
        }

        $statusLabel.Text = "Found $($membersListView.Items.Count) members"
        $membersListView.EndUpdate()
    }

    $searchBox.Add_TextChanged({
        & $updateList
    })

    $addButton.Add_Click({
        $searchDialog = New-Object System.Windows.Forms.Form
        $searchDialog.Text            = "Add Members"
        $searchDialog.Size            = New-Object System.Drawing.Size(500, 400)
        $searchDialog.StartPosition   = "CenterParent"
        $searchDialog.FormBorderStyle = "FixedDialog"
        $searchDialog.MaximizeBox     = $false
        $searchDialog.MinimizeBox     = $false

        $searchLabel = New-Object System.Windows.Forms.Label
        $searchLabel.Location = New-Object System.Drawing.Point(10, 10)
        $searchLabel.Size     = New-Object System.Drawing.Size(100, 20)
        $searchLabel.Text     = "Search:"
        $searchDialog.Controls.Add($searchLabel)

        $searchTextBox = New-Object System.Windows.Forms.TextBox
        $searchTextBox.Location = New-Object System.Drawing.Point(110, 10)
        $searchTextBox.Size     = New-Object System.Drawing.Size(370, 20)
        $searchDialog.Controls.Add($searchTextBox)

        $resultsListView = New-Object System.Windows.Forms.ListView
        $resultsListView.Location      = New-Object System.Drawing.Point(10, 40)
        $resultsListView.Size          = New-Object System.Drawing.Size(470, 280)
        $resultsListView.View          = [System.Windows.Forms.View]::Details
        $resultsListView.FullRowSelect = $true
        $resultsListView.MultiSelect   = $false
        $resultsListView.CheckBoxes    = $true
        $null = $resultsListView.Columns.Add("Name", 150)
        $null = $resultsListView.Columns.Add("Type", 100)
        $null = $resultsListView.Columns.Add("Distinguished Name", 200)
        $searchDialog.Controls.Add($resultsListView)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location     = New-Object System.Drawing.Point(405, 330)
        $okButton.Size         = New-Object System.Drawing.Size(75, 23)
        $okButton.Text         = "Add"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $searchDialog.AcceptButton = $okButton
        $searchDialog.Controls.Add($okButton)

        # Track checked results across search refreshes
        $checkedResults = [System.Collections.ArrayList]::new()
        $searchResultsCache = @{}

        $resultsListView.Add_ItemChecked({
            $item = $_.Item
            $member = $item.Tag
            if (-not $member) { return }
            $dn = [string]$member.DistinguishedName
            if (-not $dn) { return }

            if ($item.Checked) {
                if (-not $checkedResults.Contains($dn)) {
                    [void]$checkedResults.Add($dn)
                }
            }
            else {
                if ($checkedResults.Contains($dn)) {
                    [void]$checkedResults.Remove($dn)
                }
            }
        })

        $searchTextBox.Add_TextChanged({
            $resultsListView.BeginUpdate()
            $resultsListView.Items.Clear()

            # Wait for at least 3 characters to avoid overly broad AD queries
            if ($searchTextBox.Text.Length -ge 3) {
                try {
                    $searchResults = Get-ADObject -Filter "Name -like '*$($searchTextBox.Text)*'" -Properties Name, ObjectClass, DistinguishedName |
                                    Where-Object { $_.ObjectClass -in @('user', 'computer', 'group') }

                    foreach ($result in $searchResults) {
                        $item = New-Object System.Windows.Forms.ListViewItem($result.Name)
                        $item.SubItems.Add($result.ObjectClass)
                        $item.SubItems.Add($result.DistinguishedName)
                        $item.Tag = $result
                        $searchResultsCache[$result.DistinguishedName] = $result
                        $alreadyMember = $originalMembers.ContainsKey($result.DistinguishedName)
                        if ($alreadyMember -and -not $checkedResults.Contains($result.DistinguishedName)) {
                            [void]$checkedResults.Add($result.DistinguishedName)
                        }
                        if ($alreadyMember -or $checkedResults.Contains($result.DistinguishedName)) {
                            $item.Checked = $true
                        }
                        [void]$resultsListView.Items.Add($item)
                    }
                }
                catch {
                    Write-Log "Error searching for objects: $_" -Warning
                }
            }

            $resultsListView.EndUpdate()
        })

        if ($searchDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            foreach ($dn in $checkedResults) {
                if ($originalMembers.ContainsKey($dn)) { continue }
                $member = $searchResultsCache[$dn]
                if (-not $member) {
                    try { $member = Get-ADObject -Identity $dn -Properties Name, ObjectClass, DistinguishedName } catch { $member = $null }
                }
                if (-not $member) { continue }
                try {
                    Add-ADGroupMember -Identity $groupIdentity -Members $dn
                    try { Write-AuditEvent -Action 'AddGroupMember' -Target "$($groupIdentity):$($dn)" -Result 'Success' } catch {}
                    $originalMembers[$dn] = $member
                }
                catch {
                    Write-Log "Error adding member: $_" -Warning
                    [System.Windows.Forms.MessageBox]::Show(
                        "Error adding member: $_",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            }
            & $updateList
        }
    })

    # Initial population
    & $loadMembers

    $result = $dialog.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Apply removals for any members the user unchecked
        foreach ($item in $membersListView.Items) {
            if (-not $item.Checked) {
                try {
                    Remove-ADGroupMember -Identity $groupIdentity -Members $item.Tag.DistinguishedName -Confirm:$false
                    try { Write-AuditEvent -Action 'RemoveGroupMember' -Target "$($groupIdentity):$($item.Tag.DistinguishedName)" -Result 'Success' } catch {}
                }
                catch {
                    Write-Log "Error removing member: $_" -Warning
                    [System.Windows.Forms.MessageBox]::Show(
                        "Error removing member: $_",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            }
        }
        return $true
    }

    return $false
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Get-ADSecurityGroups',
    'Add-UserToSecurityGroup',
    'Remove-UserFromSecurityGroup',
    'Add-WorkstationToSecurityGroup',
    'Remove-WorkstationFromSecurityGroup',
    'Get-UserSecurityGroups',
    'Get-WorkstationSecurityGroups',
    'Show-GroupManagementDialog',
    'Show-GroupMembersDialog'
)
