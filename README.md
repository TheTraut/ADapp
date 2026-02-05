# AD App

Active Directory management application for IT administrators.

## Quick Start

- For a fast start, see `QUICKSTART.md`.
- Production install:
  - Unzip `dist/ADapp-Release.zip` (or your release zip)
  - Run `.\scripts\Install.ps1`
  - Launch `ADapp.exe`
- Uninstall with `.\scripts\Uninstall.ps1`

## Requirements

- Windows 10 or Windows Server 2016 (or newer)
- PowerShell 5.1 or newer
- .NET Framework 4.7.2 or newer
- Active Directory module for PowerShell
- Administrative access to the domain

## Configuration

ADapp uses layered configuration:

1. `config/settings.json` (tracked defaults)
2. `%ProgramData%\ADapp\config\settings.local.json` (secrets/overrides)
3. Environment variables (e.g., `ADAPP_CONNECTIONS_VNCPASSWORD`)

Example `config/settings.json`:
```json
{
  "Application": { "Title": "AD Search Tool", "Version": "1.0.16" },
  "Connections": {
    "VNCPath": "C:\\Program Files\\uvnc bvba\\UltraVNC\\vncviewer.exe",
    "VNCViewOnly": true
  },
  "AD": {
    "ADSyncDC": "your-dc",
    "ADSyncScriptPath": "C:\\Scripts\\ADSyncDelta.ps1",
    "PreferredDomainControllers": ["dc01.example.com", "dc02.example.com"]
  }
}
```

Example `%ProgramData%\ADapp\config\settings.local.json` (secrets):
```json
{
  "Connections": {
    "VNCPassword": "my-secret-password"
  }
}
```

More details in `docs/setup.md`.

## Features

- Search: users, computers, groups, and advanced filters
- User management: reset, enable/disable, unlock, group membership
- Computer management: RDP/VNC, file explorer, power actions, BitLocker recovery
- Group management: view and manage membership
- User location tracking with centralized CSV index
- Logging and auditing support

## Documentation

- Quick start: `QUICKSTART.md`
- Setup & configuration: `docs/setup.md`
- Usage guides: `docs/usage/`
- Architecture: `docs/architecture.md`
- API reference: `docs/reference/index.md`
- Dev style guide: `docs/dev/style-guide.md`

## Development

Build/test:
```powershell
.\scripts\Build.ps1
```

Common tasks:
- `.\scripts\Build.ps1 -Task Analyze`
- `.\scripts\Build.ps1 -Task Validate`
- `.\scripts\Build.ps1 -Task Build`
- `.\scripts\Build.ps1 -Task Test`

Build production package:
```powershell
.\scripts\Package-Release.ps1
```

Regenerate API docs:
```powershell
.\tools\Build-Docs.ps1
```

## File Structure

```
ADapp/
├── ADapp.ps1
├── scripts/
├── config/
├── assets/
├── docs/
├── ABOUT.md
├── QUICKSTART.md
├── CHANGELOG.md
└── Modules/
```

## Logging

- `%ProgramData%\ADapp\Logs\` - application logs
- `%ProgramData%\ADapp\Logs\ADapp_Console.log` - console output

## Support

For support or to report issues, please contact the IT department.

## License

Copyright © 2024