# Architecture

## Overview

ADapp is a modular PowerShell application with a Windows Forms UI. The main script (`ADapp.ps1`) composes UI, Active Directory operations, and helper modules to provide a cohesive management experience.

## Module Map

- `ADSearch.psm1`: Core Active Directory search and filtering utilities
- `UserManagement.psm1`: User account operations (reset, unlock, enable/disable, membership)
- `ComputerManagement.psm1`: Computer operations (RDP, VNC, Explorer, status)
- `SecurityGroups.psm1`: Group inspection and membership management
- `BitLockerRecovery.psm1`: BitLocker recovery key retrieval workflows
- `UserLocationIndex.psm1`: Centralized CSV ingest and lookup for user session locations
- `Favorites.psm1`: Save and retrieve common searches
- `SearchHistory.psm1`: Persist and display recent searches
- `PDQInventory.psm1`: Integrations with PDQ Inventory (if available)
- `QUserQuery.psm1`: Query logged-on users (WMI/QUser helpers)
- `Settings.psm1`: Load and expose configuration from `config/settings.json`
- `Transcript.psm1`: Session transcript and logging helpers
- `Logging.psm1`: Structured and file/console logging, auditing, redaction
- `UI.psm1`: UI construction, layout, sorting behavior, and dialogs

## High-level Flow

1. Startup: `ADapp.ps1` loads configuration and essential modules (`Logging`, `UI`, etc.)
2. UI Initialization: `Initialize-ADUI` builds the main form and menus; controls are exported to `$global:` for cross-module usage
3. User Actions: Search requests call into `ADSearch` and related helpers; results populate UI views
4. Management Actions: Context menus invoke `UserManagement`, `ComputerManagement`, and `SecurityGroups`
5. Logging & Audit: All significant actions use `Write-Log`/`Write-LogEvent`; optional Windows Event Log via `Write-AuditEvent`
6. User Location: On demand, `UserLocationIndex` consolidates CSV logs and performs lookups, falling back to WMI if needed

## Logging

- Logs are written to `%ProgramData%\\ADapp\\Logs\\ADapp.log` with basic rotation controls
- Structured events are JSON-serialized for easier parsing
- Sensitive data is sanitized by `Redact-SensitiveData`

## UI Notes

- ListView sorting is enabled with a dynamic comparer; column headers display up/down indicators for sort order
- Detail panels use key/value list views with contextual coloring for status fields

## Configuration

- Settings load in layers: `config/settings.json`, `%ProgramData%\ADapp\config\settings.local.json`, then environment variables
- Shared settings are persisted to `%ProgramData%\ADapp\Data\settings.json` (or `Data.PreferredSharedPath`)
- `Settings.psm1` exposes merged settings to other modules

## See also
- [[index|Home]]
- [[usage/bitlocker|BitLocker]]
- [[usage/computers|Computers]]
- [[usage/favorites-history|Favorites & History]]
- [[usage/groups|Groups]]
- [[reference/index|API Reference]]

## Related commands
- [[reference/UI/Initialize-ADUI|Initialize-ADUI]]
- [[reference/Logging/Write-Log|Write-Log]]
- [[reference/Logging/Write-LogEvent|Write-LogEvent]]
- [[reference/Logging/Write-AuditEvent|Write-AuditEvent]]
- [[reference/Logging/Redact-SensitiveData|Redact-SensitiveData]]
