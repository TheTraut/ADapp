#Requires -Version 5.1
<#
.SYNOPSIS
    UI theming and colour management module for ADapp.
.DESCRIPTION
    Provides functions to detect the Windows system theme preference, resolve
    effective theme colours from application settings, and recursively apply a
    colour palette to WinForms controls. Supports Light and Dark modes with
    configurable colour overrides.
.NOTES
    Module: Theme
    Author: ADapp Team
    Requires: System.Windows.Forms, System.Drawing assemblies
#>

#region Functions

function Get-SystemThemePreference {
    <#
    .SYNOPSIS
        Gets the Windows system theme preference (Light or Dark).
    .DESCRIPTION
        Reads the AppsUseLightTheme registry value under the current user's
        Personalize key to determine whether Windows is set to light or dark
        mode for applications. Returns 'Light' if the registry value cannot
        be read.
    .OUTPUTS
        System.String
        Either 'Light' or 'Dark'.
    .EXAMPLE
        $theme = Get-SystemThemePreference
    #>
    [CmdletBinding()]
    param ()

    try {
        $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
        $value = (Get-ItemProperty -Path $regPath -Name 'AppsUseLightTheme' -ErrorAction Stop).AppsUseLightTheme
        if ([int]$value -eq 0) { return 'Dark' } else { return 'Light' }
    }
    catch {
        return 'Light'
    }
}

function Get-EffectiveThemeMode {
    <#
    .SYNOPSIS
        Determines the effective theme mode based on settings.
    .DESCRIPTION
        Checks the UI.Theme.Mode setting and returns the appropriate mode.
        When set to 'System', delegates to Get-SystemThemePreference to read
        the Windows preference. Falls back to 'Light' on error.
    .PARAMETER Settings
        The application settings object containing UI.Theme.Mode.
    .OUTPUTS
        System.String
        Either 'Light' or 'Dark'.
    .EXAMPLE
        $mode = Get-EffectiveThemeMode -Settings $global:Settings
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Settings
    )

    try {
        $mode = try { [string]$Settings.UI.Theme.Mode } catch { 'System' }
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'System' }
        switch ($mode) {
            'Light' { return 'Light' }
            'Dark'  { return 'Dark' }
            default { return (Get-SystemThemePreference) }
        }
    }
    catch {
        return 'Light'
    }
}

function Get-EffectiveThemeColors {
    <#
    .SYNOPSIS
        Gets the effective theme colours based on current mode and settings.
    .DESCRIPTION
        Returns a colour palette object with Primary, Secondary, Background,
        and Text colours appropriate for the current theme mode (Light or Dark).
        Reads hex colour values from Settings.UI.Theme (light) or
        Settings.UI.ThemeDark (dark), falling back to sensible defaults.
    .PARAMETER Settings
        The application settings object containing UI.Theme and UI.ThemeDark.
    .OUTPUTS
        PSCustomObject
        An object with Primary, Secondary, Background, Text (System.Drawing.Color)
        and Mode (String) properties.
    .EXAMPLE
        $colors = Get-EffectiveThemeColors -Settings $global:Settings
        $form.BackColor = $colors.Background
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Settings
    )

    $mode = Get-EffectiveThemeMode -Settings $Settings
    try {
        if ($mode -eq 'Dark') {
            $p = try { [string]$Settings.UI.ThemeDark.PrimaryColor }    catch { '#3a3a3a' }
            $s = try { [string]$Settings.UI.ThemeDark.SecondaryColor }  catch { '#4a4a4a' }
            $b = try { [string]$Settings.UI.ThemeDark.BackgroundColor } catch { '#323232' }
            $t = try { [string]$Settings.UI.ThemeDark.TextColor }       catch { '#f0f0f0' }
        }
        else {
            $p = try { [string]$Settings.UI.Theme.PrimaryColor }    catch { '#4a6fba' }
            $s = try { [string]$Settings.UI.Theme.SecondaryColor }  catch { '#f0f0f0' }
            $b = try { [string]$Settings.UI.Theme.BackgroundColor } catch { '#ffffff' }
            $t = try { [string]$Settings.UI.Theme.TextColor }       catch { '#333333' }
        }

        return [PSCustomObject]@{
            Primary    = [System.Drawing.ColorTranslator]::FromHtml($p)
            Secondary  = [System.Drawing.ColorTranslator]::FromHtml($s)
            Background = [System.Drawing.ColorTranslator]::FromHtml($b)
            Text       = [System.Drawing.ColorTranslator]::FromHtml($t)
            Mode       = $mode
        }
    }
    catch {
        # Return safe defaults if colour parsing fails
        return [PSCustomObject]@{
            Primary    = [System.Drawing.Color]::FromArgb(0, 99, 177)
            Secondary  = [System.Drawing.ColorTranslator]::FromHtml('#f0f0f0')
            Background = [System.Drawing.Color]::White
            Text       = [System.Drawing.ColorTranslator]::FromHtml('#333333')
            Mode       = 'Light'
        }
    }
}

function Apply-Theme {
    <#
    .SYNOPSIS
        Applies the current theme to a control and all its children.
    .DESCRIPTION
        Recursively applies theme colours to the specified control tree,
        including special handling for MenuStrip, StatusStrip, Button, TextBox,
        ListView, ComboBox, and ToolStrip controls. Also themes any attached
        context menus. Uses an embedded C# ADAppColorTable class for custom
        ToolStrip rendering.
    .PARAMETER Root
        The root control to theme (typically the main form).
    .OUTPUTS
        None
    .EXAMPLE
        Apply-Theme -Root $mainForm
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Control]$Root
    )

    if ($null -eq $Root) { return }

    # Resolve current theme colours from settings
    $colors = Get-EffectiveThemeColors -Settings $global:Settings
    $script:primaryColor    = $colors.Primary
    $script:secondaryColor  = $colors.Secondary
    $script:backgroundColor = $colors.Background
    $script:textColor       = $colors.Text

    #region ADAppColorTable C# type (custom ToolStrip colour table)
    try {
        if (-not ([System.Management.Automation.PSTypeName]"ADAppColorTable").Type) {
            Add-Type -TypeDefinition @"
using System.Drawing;
using System.Windows.Forms;
public class ADAppColorTable : ProfessionalColorTable
{
    public static Color MyMenuStripBack = Color.FromArgb(74, 111, 186);
    public static Color MyDropDownBack = Color.White;
    public static Color MySeparatorDark = Color.FromArgb(200, 200, 200);
    public static Color MyItemSelected = Color.FromArgb(220, 220, 220);
    public static Color MyItemBorder = Color.FromArgb(200, 200, 200);

    public override Color MenuStripGradientBegin { get { return MyMenuStripBack; } }
    public override Color MenuStripGradientEnd { get { return MyMenuStripBack; } }
    public override Color ToolStripDropDownBackground { get { return MyDropDownBack; } }
    public override Color ImageMarginGradientBegin { get { return MyDropDownBack; } }
    public override Color ImageMarginGradientMiddle { get { return MyDropDownBack; } }
    public override Color ImageMarginGradientEnd { get { return MyDropDownBack; } }
    public override Color MenuBorder { get { return MyItemBorder; } }
    public override Color MenuItemBorder { get { return MyItemBorder; } }
    public override Color MenuItemSelected { get { return MyItemSelected; } }
    public override Color MenuItemSelectedGradientBegin { get { return MyItemSelected; } }
    public override Color MenuItemSelectedGradientEnd { get { return MyItemSelected; } }
    public override Color MenuItemPressedGradientBegin { get { return MyItemSelected; } }
    public override Color MenuItemPressedGradientMiddle { get { return MyItemSelected; } }
    public override Color MenuItemPressedGradientEnd { get { return MyItemSelected; } }
}
"@ -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
        }
    } catch { }
    #endregion ADAppColorTable C# type

    #region Internal helpers

    # Themes a ToolStrip (menu bar, toolbar, or dropdown)
    function Set-ToolStripTheme {
        param (
            [System.Windows.Forms.ToolStrip]$ts,
            [switch]$IsDropDown
        )
        if ($null -eq $ts) { return }
        try {
            [ADAppColorTable]::MyMenuStripBack = $script:primaryColor
            [ADAppColorTable]::MyDropDownBack  = $script:backgroundColor
            [ADAppColorTable]::MyItemBorder    = $script:secondaryColor
            [ADAppColorTable]::MySeparatorDark = $script:secondaryColor
            [ADAppColorTable]::MyItemSelected  = $script:secondaryColor

            $table = New-Object ADAppColorTable
            $ts.Renderer = New-Object System.Windows.Forms.ToolStripProfessionalRenderer($table)

            if ($IsDropDown) {
                $ts.BackColor = $script:backgroundColor
            }
            else {
                $ts.BackColor = $script:primaryColor
            }

            $ts.ForeColor = [System.Drawing.Color]::Black
            $itemForeColor = [System.Drawing.Color]::Black

            foreach ($it in $ts.Items) {
                try {
                    $it.ForeColor = $itemForeColor
                    if ($it -is [System.Windows.Forms.ToolStripMenuItem]) {
                        # Ensure text stays black even after repaints
                        $it.Add_Paint({
                            param($s, $e)
                            if ($s.ForeColor -ne [System.Drawing.Color]::Black) {
                                $s.ForeColor = [System.Drawing.Color]::Black
                            }
                        })

                        if ($it.HasDropDown) {
                            $dd = $it.DropDown
                            if ($dd) { Set-ToolStripTheme -ts $dd -IsDropDown }
                        }
                    }
                } catch { }
            }
        }
        catch {
            try { Write-Log -Message "Error setting ToolStrip theme: $_" -Level "Debug" } catch { }
        }
    }

    # Recursively applies theme colours to a control and its children
    function Apply-ThemeToControl {
        param ([System.Windows.Forms.Control]$ctl)
        if ($null -eq $ctl) { return }
        try {
            if ($ctl -is [System.Windows.Forms.MenuStrip]) {
                Set-ToolStripTheme -ts $ctl
            }
            elseif ($ctl -is [System.Windows.Forms.StatusStrip]) {
                $ctl.BackColor = $script:secondaryColor
                $ctl.ForeColor = $script:textColor
            }
            elseif ($ctl -is [System.Windows.Forms.Button]) {
                $btnColor = try {
                    if ($global:Settings.UI.SearchButtonBackColor) {
                        [System.Drawing.ColorTranslator]::FromHtml($global:Settings.UI.SearchButtonBackColor)
                    }
                    else {
                        $script:primaryColor
                    }
                } catch { $script:primaryColor }
                $ctl.BackColor = $btnColor
                $ctl.ForeColor = $script:textColor
                $ctl.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            }
            elseif ($ctl -is [System.Windows.Forms.ToolStrip]) {
                Set-ToolStripTheme -ts $ctl
            }
            elseif ($ctl -is [System.Windows.Forms.TextBox]) {
                $ctl.BackColor = $script:backgroundColor
                $ctl.ForeColor = $script:textColor
            }
            elseif ($ctl -is [System.Windows.Forms.ListView]) {
                $ctl.BackColor = $script:backgroundColor
                $ctl.ForeColor = $script:textColor
            }
            elseif ($ctl -is [System.Windows.Forms.ComboBox]) {
                $ctl.BackColor = $script:backgroundColor
                $ctl.ForeColor = $script:textColor
            }
            else {
                if ($ctl.BackColor -ne [System.Drawing.Color]::Transparent) {
                    $ctl.BackColor = $script:backgroundColor
                }
                $ctl.ForeColor = $script:textColor
            }

            # Theme any attached context menu
            try {
                $cms = $ctl.ContextMenuStrip
                if ($cms) { Set-ToolStripTheme -ts $cms -IsDropDown }
            } catch { }
        } catch { }

        foreach ($child in $ctl.Controls) { Apply-ThemeToControl -ctl $child }
    }

    #endregion Internal helpers

    Apply-ThemeToControl -ctl $Root
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-SystemThemePreference, Get-EffectiveThemeMode, Get-EffectiveThemeColors, Apply-Theme
