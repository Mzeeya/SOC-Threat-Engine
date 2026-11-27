#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef ProjectRoot
  #define ProjectRoot "."
#endif
#ifndef InstallerOutput
  #define InstallerOutput "dist\installer"
#endif

[Setup]
AppId={{B4CC23D4-1B4F-4F91-9A2D-15A3302BE731}
AppName=SOC Threat Engine
AppVersion={#AppVersion}
AppPublisher=SOC Threat Engine
DefaultDirName={localappdata}\Programs\SOC Threat Engine
DefaultGroupName=SOC Threat Engine
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#InstallerOutput}
OutputBaseFilename=SOCLogAnalyzer-Setup
SetupIconFile={#ProjectRoot}\static\SocThreatEngine.ico
UninstallDisplayIcon={app}\SOCLogAnalyzer.exe
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#ProjectRoot}\dist\SOCLogAnalyzer\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\SOC Threat Engine"; Filename: "{app}\SOCLogAnalyzer.exe"; WorkingDir: "{app}"
Name: "{autoprograms}\Uninstall SOC Threat Engine"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SOC Threat Engine"; Filename: "{app}\SOCLogAnalyzer.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\SOCLogAnalyzer.exe"; Description: "Launch SOC Threat Engine"; Flags: nowait postinstall skipifsilent
