@echo off

:: Elevate to admin to apply reg tweaks
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

:: Restore nvidiaProfileInspector settings
where nvidiaProfileInspector 1>nul 2>nul
if %ERRORLEVEL% EQU 0 (
    nvidiaProfileInspector.exe -silentImport "%~dp0nvidiaProfileInspector\Default.nip"
    choco uninstall nvidia-profile-inspector -y
    echo.
)
call :bcdedit /deletevalue vsmlaunchtype

call :bcdedit /deletevalue x2apicpolicy
call :bcdedit /deletevalue configaccesspolicy

call :bcdedit /deletevalue useplatformclock
call :bcdedit /deletevalue useplatformtick
call :bcdedit /deletevalue disabledynamictick
call :bcdedit /deletevalue tscsyncpolicy
::call :bcdedit /set disabledynamictick no

REG delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f 2>nul
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSi /f 2>nul
REG add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "400" /f
REG add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "1" /f

REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 0x0 /f

REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /f 2>nul

REG add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 0x2 /f

REG add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0x64 /f
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /f 2>nul

::REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0x14 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xA /f

REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /f 2>nul
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x3 /f
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /f 2>nul

REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x2 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 0x2 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "Normal" /f

REG delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /f 2>nul

REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /f 2>nul

REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /f 2>nul
REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /f 2>nul

echo.

tasklist /fi "ImageName eq SetTimerResolution.exe" /fo csv 2>NUL | find /I "SetTimerResolution.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo SetTimerResolution.exe is already disabled and removed!
    :: echo if you wish to install and enable it again, use Tweaks.bat
    echo.
)
taskkill /f /im SetTimerResolution.exe 1>nul 2>nul
del /Q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SetTimerResolution.exe.lnk" 1>nul 2>nul
del /Q "C:\Windows\SetTimerResolution.exe" 1>nul 2>nul

echo Restarting Explorer...
taskkill /im explorer.exe /f 1>nul 2>nul
start /B explorer.exe
echo.
echo Successfully restored all tweaks!
call Tools\colortext 0C "REBOOT REQUIRED" 1
echo Press any key to close...
pause >nul
exit


exit /b
:: Define functions here.
:bcdedit
bcdedit %* 2>nul | find /i "The operation completed successfully." >nul && echo The operation completed successfully.
exit /b