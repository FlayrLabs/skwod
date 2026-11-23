; skwod host — Windows installer (NSIS, per-user: no administrator rights needed).
;
;   makensis -DVERSION=0.0.0 -DSRC=<dir with the .exe files> -DOUTFILE=<setup.exe> installer.nsi
;
; STATUS: not compiled or run yet (see host/packaging/build.sh). The installer is unsigned:
; SmartScreen will warn until the release is code-signed.
;
; Installs to %LOCALAPPDATA%\Programs\skwod host. The server's data (database, keys — your
; server's address) lives in %LOCALAPPDATA%\skwod-host and is NOT removed by the uninstaller.

Unicode true
!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SRC
  !error "pass -DSRC=<directory containing skwod-host.exe, skwod.exe, livekit-server.exe>"
!endif
!ifndef OUTFILE
  !define OUTFILE "skwod-host-setup.exe"
!endif

!define APP "skwod host"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\skwod-host"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${APP}"
OutFile "${OUTFILE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\skwod host"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
SetCompressor /SOLID lzma
!define MUI_ICON "${SRC}\skwod-host.ico"
!define MUI_UNICON "${SRC}\skwod-host.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SRC}\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\skwod-host.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start skwod host"
!define MUI_FINISHPAGE_TEXT "skwod host lives in the notification area (next to the clock).$\r$\n$\r$\nThe first time you press Start server, Windows may ask whether skwod may communicate on your networks. Choose Allow: it lets your friends connect straight to this PC. If you choose Cancel, skwod still works through a relay, only slower."
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File "${SRC}\skwod-host.exe"
  File "${SRC}\skwod.exe"
  File "${SRC}\livekit-server.exe"
  File "${SRC}\skwod-host.ico"
  File "${SRC}\LICENSE.txt"
  File "${SRC}\THIRD-PARTY-NOTICES.md"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\skwod-host.exe" "" "$INSTDIR\skwod-host.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\skwod-host.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ; "Launch at login" (set from the tray menu) points at the program being removed.
  DeleteRegValue HKCU "${RUN_KEY}" "skwod-host"
  Delete "$SMPROGRAMS\${APP}.lnk"
  Delete "$INSTDIR\skwod-host.exe"
  Delete "$INSTDIR\skwod.exe"
  Delete "$INSTDIR\livekit-server.exe"
  Delete "$INSTDIR\skwod-host.ico"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
  ; %LOCALAPPDATA%\skwod-host (the server's database and keys) is left in place on purpose.
SectionEnd
