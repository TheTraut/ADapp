# Setup

## Requirements

- Windows 10 or Windows Server 2016 (or newer)
- PowerShell 5.1 or newer
- .NET Framework 4.7.2 or newer
- Active Directory PowerShell module
- Administrative privileges for AD operations

## Installation

1. Copy/clone the `ADapp` folder to a local path
2. Ensure required PowerShell modules are available (ActiveDirectory)
3. Start the application:
   - `ADapp.exe`, or
   - `ADapp.ps1` (Run as Administrator)

## Configuration

ADapp uses a layered configuration system:

1. **`config/settings.json`** (tracked in git) — shared defaults and non-sensitive settings
2. **`%ProgramData%\ADapp\config\settings.local.json`** — machine-specific secrets and overrides
3. **Environment variables** — automation-friendly overrides (e.g., `ADAPP_CONNECTIONS_VNCPASSWORD`)

Settings are merged at startup: `config/settings.json` → `%ProgramData%\ADapp\config\settings.local.json` → environment variables.

### Secrets

**Never commit secrets to `config/settings.json` or shared settings.** For values like `VNCPassword`, use one of:

- Copy `config/settings.local.json.example` to `%ProgramData%\ADapp\config\settings.local.json` and fill in secrets (recommended)
- Set the `ADAPP_CONNECTIONS_VNCPASSWORD` environment variable

Notes:
- Shared settings are saved to `%ProgramData%\ADapp\Data\settings.json` (or `Data.PreferredSharedPath` if configured) and are sanitized to remove secrets automatically.
- Secrets are persisted only in `%ProgramData%\ADapp\config\settings.local.json` (local machine) or environment variables.

### Configuration Sections

| Section | Purpose |
|---------|---------|
| `Application` | Window title, version, form size |
| `UI` | Theme colors, fonts |
| `Search` | Max results, history size, defaults |
| `AD` | Domain controller, sync script path |
| `Connections` | VNC/RDP paths, timeouts, credentials |
| `Logging` | Log path, rotation, verbosity |
| `PDQ` | PDQ Inventory integration |
| `QUser` | Logged-on user queries |
| `Shortcuts` | Keyboard shortcuts |
| `Monitor` | Locked Users Monitor settings |

### Example config/settings.json

```json
{
  "Application": { "Title": "AD Search Tool", "Version": "1.0.16" },
  "Connections": {
    "VNCPath": "C:\\Program Files\\uvnc bvba\\UltraVNC\\vncviewer.exe",
    "VNCPassword": "",
    "VNCViewOnly": true
  },
  "AD": {
    "ADSyncDC": "your-dc",
    "ADSyncScriptPath": "C:\\Scripts\\ADSyncDelta.ps1",
    "PreferredDomainControllers": ["dc01.example.com", "dc02.example.com"]
  }
}
```

### Example %ProgramData%\ADapp\config\settings.local.json

```json
{
  "Connections": {
    "VNCPassword": "my-secret-password"
  }
}
```

## Logging

- Application logs: `%ProgramData%\\ADapp\\Logs\\` (rotated automatically)
- Console log stream may be reduced for Info messages to keep the console signal high

## Troubleshooting

- Run as Administrator when performing AD operations
- Ensure Windows Forms assemblies are present (PowerShell 5.1 on Windows)
- Check `%ProgramData%\\ADapp\\Logs\\ADapp.log` for details and errors

## See also
- [[index|Home]]
- [[usage/bitlocker|BitLocker]]
- [[usage/computers|Computers]]
- [[usage/favorites-history|Favorites & History]]
- [[usage/groups|Groups]]
- [[reference/index|API Reference]]
