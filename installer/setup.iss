; PersonaCore-Agent Inno Setup script (SPEC-10).
;
; Build with:
;     iscc installer/setup.iss /DAppVersion=0.1.0
;
; Produces: dist/PersonaCore-Agent-Setup-<version>.exe
;
; Layout:
;     <install>/
;         app/<version>/          — PyInstaller bundle + Updater.exe
;         current -> app/<version>/ (junction, updater swaps it)
;
; Startup registration branches:
;     Per-user      : HKCU\Software\Microsoft\Windows\CurrentVersion\Run
;     Machine-wide  : Task Scheduler task "WorkstationAgent\Startup"

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

#define AppName        "PersonaCore Agent"
#define AppPublisher   "PersonaCore"
#define AppExeName     "Agent.exe"
#define AppMutex       "Global\PersonaCore-Agent-Installer"
#define UpdaterExeName "Updater.exe"

[Setup]
AppId={{7F4B1F0B-8B45-4E6B-8A5A-6E9CFCC0D9A2}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={code:GetDefaultDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputBaseFilename=PersonaCore-Agent-Setup-{#AppVersion}
OutputDir=..\dist
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog
UninstallDisplayIcon={app}\current\{#AppExeName}
UninstallDisplayName={#AppName}
AppMutex={#AppMutex}
ArchitecturesInstallIn64BitMode=x64
UsePreviousAppDir=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart_hkcu";  Description: "Start {#AppName} at logon (this user)"; \
    GroupDescription: "Startup:"; Flags: unchecked; Check: IsPerUser
Name: "autostart_task";  Description: "Start {#AppName} at logon (all users, via Task Scheduler)"; \
    GroupDescription: "Startup:"; Flags: unchecked; Check: IsAdminInstall

[Files]
; Application binaries — installed under {app} which resolves per install
; mode: {localappdata}\WorkstationAgent (per-user) or {pf}\WorkstationAgent
; (machine-wide), chosen by GetDefaultDir() below.  The [Files] section is
; identical in both modes; only the destination root differs.
Source: "..\dist\Agent\*"; DestDir: "{app}\app\{#AppVersion}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\{#UpdaterExeName}"; DestDir: "{app}\app\{#AppVersion}"; \
    Flags: ignoreversion
; Per-user config seed: writable data dir under %APPDATA% (never
; %ProgramData%) so the per-user branch never needs elevation to write.
Source: "..\dist\Agent\Agent.exe"; DestDir: "{userappdata}\WorkstationAgent"; \
    Flags: onlyifdoesntexist skipifsourcedoesntexist external dontcopy; \
    Check: IsPerUser
; Machine-wide config seed lives under %ProgramData% so all users share.
Source: "..\dist\Agent\Agent.exe"; DestDir: "{commonappdata}\WorkstationAgent"; \
    Flags: onlyifdoesntexist skipifsourcedoesntexist external dontcopy; \
    Check: IsAdminInstall

[Dirs]
; Ensure a writable data dir exists in the correct scope.  Per-user goes to
; %APPDATA%, machine-wide goes to %ProgramData% (world-writable ACL is
; explicitly NOT granted — services expect elevated writers only).
Name: "{userappdata}\WorkstationAgent";   Check: IsPerUser
Name: "{commonappdata}\WorkstationAgent"; Check: IsAdminInstall

[Icons]
Name: "{group}\{#AppName}";       Filename: "{app}\current\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Registry]
; Per-user auto-start uses HKCU Run — no admin required.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueName: "WorkstationAgent"; ValueType: string; \
    ValueData: """{app}\current\{#AppExeName}"" --autostart"; \
    Flags: uninsdeletevalue; Tasks: autostart_hkcu; Check: IsPerUser
; Machine-wide install records the installed version under HKLM (audit trail;
; the actual Run key is NOT used since HKLM\Run would run in the target user
; context anyway — we use Task Scheduler instead for admin installs).
Root: HKLM; Subkey: "Software\{#AppPublisher}\{#AppName}"; \
    ValueName: "InstallVersion"; ValueType: string; ValueData: "{#AppVersion}"; \
    Flags: uninsdeletekey; Check: IsAdminInstall

[Run]
; Machine-wide install → register a Task Scheduler job at logon.  This is
; guarded by BOTH the Tasks flag (user opt-in) and Check (install mode).
Filename: "schtasks.exe"; \
    Parameters: "/create /F /TN ""WorkstationAgent\Startup"" /TR ""\""{app}\current\{#AppExeName}\"" --autostart"" /SC ONLOGON /RL LIMITED"; \
    Flags: runhidden; Tasks: autostart_task; Check: IsAdminInstall
; Optional: launch the app after install (default checked on Finish page).
; Use the direct versioned path (NOT the junction) + shellexec so Inno's
; postinstall launcher doesn't crash with "CreateProcess failed; code 2" —
; the junction is real (verified via mklink+dir /A:L) but something about
; how Inno's postinstall Run resolves it on some machines is broken. The
; direct path bypasses that entirely. The junction still exists and the
; Start Menu shortcut + Registry Run key still use `current\` so future
; updates via the updater EXE swap correctly.
Filename: "{app}\app\{#AppVersion}\{#AppExeName}"; \
    WorkingDir: "{app}\app\{#AppVersion}"; \
    Description: "Launch {#AppName}"; \
    Flags: postinstall skipifsilent nowait shellexec

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/delete /F /TN ""WorkstationAgent\Startup"""; \
    Flags: runhidden; RunOnceId: "DelStartupTask"; Check: IsAdminInstall

[UninstallDelete]
Type: filesandordirs; Name: "{app}\app"
Type: files; Name: "{app}\current"
; NOTE: %APPDATA%\WorkstationAgent (per-user config, secrets, conversations,
; logs) and %ProgramData%\WorkstationAgent (machine-wide seed) are
; intentionally NOT removed on uninstall. See MessagesFile below.

[Messages]
UninstalledAll=%1 was successfully removed.%n%nYour data folder (%APPDATA%\WorkstationAgent) was left in place. Delete it manually if you no longer need it.

[Code]
function IsPerUser(): Boolean;
begin
  Result := not IsAdminInstallMode();
end;

function IsAdminInstall(): Boolean;
begin
  Result := IsAdminInstallMode();
end;

function GetDefaultDir(Param: String): String;
begin
  if IsAdminInstallMode() then
    Result := ExpandConstant('{pf}\WorkstationAgent')
  else
    Result := ExpandConstant('{localappdata}\WorkstationAgent');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  CurrentDir, VersionDir: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    CurrentDir  := ExpandConstant('{app}\current');
    VersionDir  := ExpandConstant('{app}\app\{#AppVersion}');
    // Remove any pre-existing junction/dir at "current" then create a fresh one.
    if DirExists(CurrentDir) then
      Exec(ExpandConstant('{cmd}'), '/C rmdir "' + CurrentDir + '"',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{cmd}'),
         '/C mklink /J "' + CurrentDir + '" "' + VersionDir + '"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
