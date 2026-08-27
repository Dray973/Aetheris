; Aetheris Quantum Core - SELF-CONTAINED installer (recommended for distribution)
;
; Wraps the frozen one-file dist\AetherisQuantumCore.exe. The target machine
; needs NOTHING installed - no Python, no internet, no dependencies. This is the
; "install on anyone's computer" path.
;
; Build steps:
;   1) build the exe:   powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1
;   2) install Inno Setup 6:  https://jrsoftware.org/isdl.php
;   3) compile:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\aetheris_exe.iss
;   -> produces installer\Output\AetherisQuantumCoreSetup.exe  (hand this to anyone)

#define AppName "Aetheris Quantum Core"
#define AppVersion "0.1.0"
#define AppExe "AetherisQuantumCore.exe"

[Setup]
AppId={{9F2C6E1A-3B7D-4A55-9E10-AE7HER15FR0Z}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Aetheris
DefaultDirName={autopf}\Aetheris Quantum Core
DisableProgramGroupPage=yes
OutputBaseFilename=AetherisQuantumCoreSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName={#AppName}
SetupIconFile=..\aetheris\ui\assets\aetheris.ico
UninstallDisplayIcon={app}\{#AppExe}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; The single frozen executable - self-contained (Python + all deps inside).
Source: "..\dist\AetherisQuantumCore.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; \
    Flags: postinstall nowait skipifsilent
