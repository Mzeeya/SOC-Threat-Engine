$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$python = $null

$uv = Get-Command uv -ErrorAction SilentlyContinue
if ($uv) {
    $uvPython = & $uv.Source python find 3.13
    if ($LASTEXITCODE -eq 0 -and $uvPython) {
        $python = @($uvPython.Trim())
    }
}

if (-not $python) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $availableRuntimes = & $pyLauncher.Source --list-paths 2>&1 | Out-String
        $match = [regex]::Match(
            $availableRuntimes,
            '(?m)^\s*-V:3\.13[^\s]*\s+\*?\s*(?<path>.+python\.exe)\s*$'
        )
        if ($match.Success) {
            $python = @($match.Groups["path"].Value.Trim())
        }
    }
}

if (-not $python) {
    throw "Python 3.13 is required. Install it, then rerun build-exe.ps1."
}

$venvPath = Join-Path $projectRoot ".venv-build"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $pythonCommand = $python[0]
    $pythonArguments = @($python | Select-Object -Skip 1)
    & $pythonCommand @pythonArguments -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the build environment."
    }
}

& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Could not prepare pip in the build environment."
}
& $venvPython -m pip install -r (Join-Path $projectRoot "requirements-build.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the application and packaging dependencies."
}

$distPath = Join-Path $projectRoot "dist"
$buildPath = Join-Path $projectRoot "build"
& $venvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --console `
    --name SOCLogAnalyzer `
    --icon (Join-Path $projectRoot "static\SocThreatEngine.ico") `
    --distpath $distPath `
    --workpath (Join-Path $buildPath "pyinstaller") `
    --specpath $buildPath `
    --add-data "$projectRoot\templates;templates" `
    --add-data "$projectRoot\static;static" `
    (Join-Path $projectRoot "launcher.py")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to build the executable."
}

& $venvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name SOCLogAnalyzer-Portable `
    --icon (Join-Path $projectRoot "static\SocThreatEngine.ico") `
    --distpath $distPath `
    --workpath (Join-Path $buildPath "pyinstaller-portable") `
    --specpath $buildPath `
    --add-data "$projectRoot\templates;templates" `
    --add-data "$projectRoot\static;static" `
    (Join-Path $projectRoot "launcher.py")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to build the portable executable."
}

$compilerCommand = Get-Command iscc -ErrorAction SilentlyContinue
$compilerPath = if ($compilerCommand) { $compilerCommand.Source } else { $null }
if (-not $compilerPath) {
    $compilerPaths = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $compilerPaths) {
        if (Test-Path $candidate) {
            $compilerPath = $candidate
            break
        }
    }
}

if ($compilerPath) {
    $installerOutput = Join-Path $distPath "installer"
    New-Item -ItemType Directory -Force -Path $installerOutput | Out-Null
    & $compilerPath "/DAppVersion=1.0.1" "/DProjectRoot=$projectRoot" `
        "/DInstallerOutput=$installerOutput" `
        (Join-Path $projectRoot "installer.iss")
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup failed to build the installer."
    }
    Write-Output "Installer created: $(Join-Path $installerOutput 'SOCLogAnalyzer-Setup.exe')"
} else {
    Write-Warning "Inno Setup 6 was not found. The app executable is ready; install Inno Setup 6 and rerun this script to create the installer."
}

Write-Output "Application executable: $(Join-Path $distPath 'SOCLogAnalyzer\SOCLogAnalyzer.exe')"
Write-Output "Portable executable: $(Join-Path $distPath 'SOCLogAnalyzer-Portable.exe')"
