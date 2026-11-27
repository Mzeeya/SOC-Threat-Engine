# SOC Threat Engine for Windows

## Install

Run `SOCLogAnalyzer-Setup.exe` and follow the prompts. The per-user installer
does not require administrator access. It adds Start Menu shortcuts to launch
and uninstall the app, offers an optional desktop shortcut, and registers a
Windows uninstaller in Installed apps.

## Use

Open **SOC Threat Engine** from the Start Menu. The app starts a local web server
bound only to `127.0.0.1` and opens the dashboard in your default browser. Keep
the console window open while using the dashboard; press Enter in that window
to stop the app. Uploaded CSV data is analyzed in memory and is not saved by
the app.

## Build the executable and installer

Requirements: Windows, Python 3.13, PowerShell, and Inno Setup 6.

From this directory, run:

```powershell
.\build-exe.ps1
```

The script creates a local `.venv-build` environment, installs the dependencies
from `requirements-build.txt`, builds the app, and compiles the installer when
Inno Setup 6 is available.

Build outputs:

- `dist\SOCLogAnalyzer\SOCLogAnalyzer.exe` — executable and its supporting files
- `dist\SOCLogAnalyzer-Portable.exe` — standalone portable executable
- `dist\installer\SOCLogAnalyzer-Setup.exe` — Windows installer

The installer uses a directory bundle for faster, more reliable startup. The
additional portable build is a single executable that extracts its bundled
files when launched.

The binaries are not code-signed. Windows SmartScreen may show an unknown
publisher warning when launching a locally built installer.
