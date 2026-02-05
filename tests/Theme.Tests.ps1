#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for the Theme module.
#>

Describe 'Get-SystemThemePreference' {
    BeforeAll {
        # Load WinForms for color types
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        
        $modulePath = Join-Path $PSScriptRoot '..\Modules\Theme.psm1'
        Import-Module $modulePath -Force
    }
    It 'Should return Light or Dark' {
        $result = Get-SystemThemePreference
        $result | Should Match '^(Light|Dark)$'
    }
}

Describe 'Get-EffectiveThemeMode' {
    Context 'When Mode is explicitly set' {
        It 'Should return Light when set to Light' {
            $settings = [PSCustomObject]@{
                UI = [PSCustomObject]@{
                    Theme = [PSCustomObject]@{ Mode = 'Light' }
                }
            }
            $result = Get-EffectiveThemeMode -Settings $settings
            $result | Should Be 'Light'
        }
        
        It 'Should return Dark when set to Dark' {
            $settings = [PSCustomObject]@{
                UI = [PSCustomObject]@{
                    Theme = [PSCustomObject]@{ Mode = 'Dark' }
                }
            }
            $result = Get-EffectiveThemeMode -Settings $settings
            $result | Should Be 'Dark'
        }
    }
    
    Context 'When Mode is System or empty' {
        It 'Should fall back to system preference' {
            $settings = [PSCustomObject]@{
                UI = [PSCustomObject]@{
                    Theme = [PSCustomObject]@{ Mode = 'System' }
                }
            }
            $result = Get-EffectiveThemeMode -Settings $settings
            $result | Should Match '^(Light|Dark)$'
        }
    }
}

Describe 'Get-EffectiveThemeColors' {
    BeforeAll {
        $lightSettings = [PSCustomObject]@{
            UI = [PSCustomObject]@{
                Theme = [PSCustomObject]@{
                    Mode = 'Light'
                    PrimaryColor = '#4a6fba'
                    SecondaryColor = '#f0f0f0'
                    BackgroundColor = '#ffffff'
                    TextColor = '#333333'
                }
                ThemeDark = [PSCustomObject]@{
                    PrimaryColor = '#3a3a3a'
                    SecondaryColor = '#4a4a4a'
                    BackgroundColor = '#323232'
                    TextColor = '#f0f0f0'
                }
            }
        }
        
        $darkSettings = [PSCustomObject]@{
            UI = [PSCustomObject]@{
                Theme = [PSCustomObject]@{
                    Mode = 'Dark'
                    PrimaryColor = '#4a6fba'
                    SecondaryColor = '#f0f0f0'
                    BackgroundColor = '#ffffff'
                    TextColor = '#333333'
                }
                ThemeDark = [PSCustomObject]@{
                    PrimaryColor = '#3a3a3a'
                    SecondaryColor = '#4a4a4a'
                    BackgroundColor = '#323232'
                    TextColor = '#f0f0f0'
                }
            }
        }
    }
    
    It 'Should return color object with all required properties' {
        $result = Get-EffectiveThemeColors -Settings $lightSettings
        $result.Primary | Should Not BeNullOrEmpty
        $result.Secondary | Should Not BeNullOrEmpty
        $result.Background | Should Not BeNullOrEmpty
        $result.Text | Should Not BeNullOrEmpty
        $result.Mode | Should Not BeNullOrEmpty
    }
    
    It 'Should return light colors when mode is Light' {
        $result = Get-EffectiveThemeColors -Settings $lightSettings
        $result.Mode | Should Be 'Light'
        # Light theme typically has white background
        $result.Background.R | Should BeGreaterThan 200
    }
    
    It 'Should return dark colors when mode is Dark' {
        $result = Get-EffectiveThemeColors -Settings $darkSettings
        $result.Mode | Should Be 'Dark'
        # Dark theme typically has dark background
        $result.Background.R | Should BeLessThan 100
    }
}
