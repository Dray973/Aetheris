; Aetheris Quantum Core - Inno Setup script
; Produces a single AetherisSetup.exe that installs the program and then
; bootstraps a Python venv with all dependencies (downloaded on first install).
;
; Build: install Inno Setup 6 (https://jrsoftware.org/isdl.php), then either
;   open this file in the Inno Setup Compiler and press F9, or run:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\aetheris.iss
; The compiled installer lands in installer\Output\AetherisSetup.exe

#define AppName "Aetheris Quantum Core"
#define AppVersion "0.1.0"
#define AppPublisher "Aetheris"

[Setup]
AppId={{9F2C6E1A-3B7D-4A55-9E10-AE7H3R15C0RE}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Aetheris Quantum Core
DefaultGroupName=Aetheris Quantum Core
DisableProgramGroupPage=yes
OutputBaseFilename=AetherisSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName={#AppName}
SetupIconFile=..\aetheris\ui\assets\aetheris.ico
UninstallDisplayIcon={app}\aetheris\ui\assets\aetheris.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\aetheris\*";       DestDir: "{app}\aetheris"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\run.py";           DestDir: "{app}"; Flags: ignoreversion
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";        DestDir: "{app}"; Flags: ignoreversion
Source: "..\pyproject.toml";   DestDir: "{app}"; Flags: ignoreversion
Source: "bootstrap.ps1";       DestDir: "{app}\installer"; Flags: ignoreversion
Source: "uninstall.ps1";       DestDir: "{app}\installer"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\.venv\Scripts\pythonw.exe"; \
    Parameters: """{app}\run.py"""; WorkingDir: "{app}"; \
    IconFilename: "{app}\aetheris\ui\assets\aetheris.ico"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\.venv\Scripts\pythonw.exe"; \
    Parameters: """{app}\run.py"""; WorkingDir: "{app}"; Tasks: desktopicon; \
    IconFilename: "{app}\aetheris\ui\assets\aetheris.ico"

[Run]
; This is the "download everything you need" step, run after files are laid down.
Filename: "powershell.exe"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\bootstrap.ps1"" -InstallDir ""{app}"""; \
    StatusMsg: "Downloading and installing Python + dependencies (this can take a few minutes)..."; \
    Flags: waituntilterminated
; Offer to launch on finish.
Filename: "{app}\.venv\Scripts\pythonw.exe"; Parameters: """{app}\run.py"""; \
    Description: "Launch {#AppName}"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
; Remove the venv and any pyc caches created after install.
Type: filesandordirs; Name: "{app}\.venv"
Type: filesandordirs; Name: "{app}\aetheris\__pycache__"
