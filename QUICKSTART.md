# AD App Quick Start

Use this guide for a production install. For full setup and configuration, see the GitHub repo docs (`docs/setup.md`).

## Install

1. Unzip the production release package.
2. Run the installer:
   - `.\scripts\Install.ps1`
   - Optional: `.\scripts\Install.ps1 -SkipShortcuts`
3. Launch the app:
   - `ADapp.exe`, or
   - `ADapp.ps1` (Run as Administrator)

## Configure secrets (recommended)

- Copy `config/settings.local.json.example` to:
  `%ProgramData%\ADapp\config\settings.local.json`
- Set `Connections.VNCPassword` there (or use env var `ADAPP_CONNECTIONS_VNCPASSWORD`).

## Uninstall

- Run `.\scripts\Uninstall.ps1`

## Need more?

- Full setup/configuration: `docs/setup.md` (GitHub repo)
- Usage guides: `docs/usage/` (GitHub repo)

