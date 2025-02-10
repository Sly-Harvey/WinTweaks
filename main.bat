@echo off
Setlocal EnableDelayedExpansion



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
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 5 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
    powershell set-executionpolicy remotesigned
:--------------------------------------
::color B

for /F "tokens=*" %%F IN ('powershell "Get-CimInstance -Namespace root\cimv2 -ClassName Win32_VideoController | Select-Object -ExpandProperty CurrentRefreshRate"') DO (
set REFRESH_RATE=%%F
set /a GSYNC_CAP=REFRESH_RATE-3
)

:: reference: https://documentation.help/nvWmi-win10/profileSettings.html
:: 1620202130 = app controlled vsync
:: 1199655232 = force on vsync
:: 138504007 = force off vsync
set /p choiceGsync=Set up gsync + vsync + fps cap -3 below refresh rate? (y/N): 
echo.
if "%choiceGsync%"=="y" (
    powershell -ExecutionPolicy Bypass -File "Tools\vsync.ps1" -value 1199655232 -filePath "Programs\nvidiaProfileInspector\Performance.nip"
    powershell -ExecutionPolicy Bypass -File "Tools\fpsLimiter.ps1" -Add -FPS %GSYNC_CAP% -filePath "Programs\nvidiaProfileInspector\Performance.nip"
) else if "%choiceGsync%"=="Y" (
    powershell -ExecutionPolicy Bypass -File "Tools\vsync.ps1" -value 1199655232 -filePath "Programs\nvidiaProfileInspector\Performance.nip"
    powershell -ExecutionPolicy Bypass -File "Tools\fpsLimiter.ps1" -Add -FPS %GSYNC_CAP% -filePath "Programs\nvidiaProfileInspector\Performance.nip"
) else (
    powershell -ExecutionPolicy Bypass -File "Tools\vsync.ps1" -value 1620202130 -filePath "Programs\nvidiaProfileInspector\Performance.nip"
    powershell -ExecutionPolicy Bypass -File "Tools\fpsLimiter.ps1" -Delete -filePath "Programs\nvidiaProfileInspector\Performance.nip"
)
echo.

:: Enable nvidiaProfileInspector settings
::where nvidiaProfileInspector 1>nul 2>nul
::if %ERRORLEVEL% NEQ 0 (
::    where choco 1>nul 2>nul
::    if %ERRORLEVEL% NEQ 0 (
::        PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Tools\chocolatey.ps1"
::        call "Tools\RefreshEnv.cmd"
::        choco feature enable -n allowGlobalConfirmation
::    )
::    choco install nvidia-profile-inspector -y
::) else echo nvidiaProfileInspector is already installed!
Programs\nvidiaProfileInspector\nvidiaProfileInspector.exe -silentImport "%~dp0Programs\nvidiaProfileInspector\Performance.nip"
echo.

:: Boosted memory performance and improved microstuttering
call :bcdedit /set firstmegabytepolicy UseAll
call :bcdedit /set avoidlowmemory 0x8000000
call :bcdedit /set nolowmem Yes

:: Disabled DMA memory protection and cores isolation
:: Might enable this feature again for security
call :bcdedit /set vsmlaunchtype Off

:: Enabled X2Apic and enable Memory Mapping for PCI-E devices
call :bcdedit /set x2apicpolicy Enable
call :bcdedit /set configaccesspolicy Default

:: Use TSC in favour of HPET and disable dynamic tick rates, this results in lower latency
:: In the event of higher cpu usage or laptop then delete disabledynamictick
:: In the event of higher latency then delete tscsyncpolicy
call :bcdedit /set useplatformclock no
call :bcdedit /set useplatformtick no
call :bcdedit /set disabledynamictick yes
call :bcdedit /set tscsyncpolicy Enhanced

:: User HPET with dynamic ticks disabled
::bcdedit /set useplatformtick yes
::bcdedit /set disabledynamictick yes
::bcdedit /deletevalue useplatformclock 

:: Appearance
REG ADD "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSi /t REG_DWORD /d 0x0 /f
REG ADD "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "8" /f
REG ADD "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "0" /f

:: Timer Resolution Fix (Important)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 0x1 /f

:: bypass hardware and secure boot checks
REG ADD "HKLM\SYSTEM\Setup\LabConfig\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 0x1 /f

:: Make startup apps load faster (May cause issues since they load before system services)
::REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayinMSec /t REG_DWORD /d 0x1 /f
::REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v WaitForIdleState /t REG_DWORD /d 0x0 /f

:: All values are in hex format
:: 2A Hex = Short, Fixed , High foreground boost.
:: 29 Hex = Short, Fixed , Medium foreground boost.
:: 28 Hex = Short, Fixed , No foreground boost.
:: 26 Hex = Short, Variable , High foreground boost.
:: 25 Hex = Short, Variable , Medium foreground boost.
:: 24 Hex = Short, Variable , No foreground boost.
:: 1A Hex = Long, Fixed, High foreground boost.
:: 19 Hex = Long, Fixed, Medium foreground boost.
:: 18 Hex = Long, Fixed, No foreground boost.
:: 16 Hex = Long, Variable, High foreground boost.
:: 15 Hex = Long, Variable, Medium foreground boost.
:: 14 Hex = Long, Variable, No foreground boost.
:: 2 = Windows Default

:: Favourites:
:: 24/26 (Current)
:: 14/16
:: 2A/28

:: From my research it appears that no foreground boost may be better (if your system is modern)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x24 /f

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d 0x1 /f

:: Decrease mouse and keyboard buffer sizes (USE WITH CAUTION)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 0xC /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d 0x10 /f

:: More mouse tweaks for input latency and smoothness
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d 0x1F /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d 0x2710 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d 0x5 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d 0x28 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d 0x32 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d 0xA /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d 0x168 /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 000000000000000000000000000000000000000000000000C0CC0C000000000000000000000000000809919000000000000000000000000406626000000000000000000000000003333000000000000 /f
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 000000000000000000000000000000000000000000000000000038000000000000000000000000000000000070000000000000000000000000000000000A800000000000000000000000000000000E000000000000000000000000000000 /f

:: Disable MPO (Multi plane overlay)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 0x5 /f

:: system and network tweaks
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xA /f

:: HAGS (Hardware accelerated gpu scheduling) 2 = on, 1 = off
:: Offloads CPU task to the GPU
:: I keep this off since i get lower temperatures
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 0x1 /f

:: Memory tweaks (testing LargeSystemCache = off)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d 0x1 /f
::REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d 0x1 /f

:: Speed up HDD (IoPageLockLimit = 512kb * 100)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v IoPageLockLimit /t REG_DWORD /d 0x51200 /f

:: Game Priority
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x8 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 0x6 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

:: Use realtime priority for csrss.exe. (4 = realtime, 3 = high)
::REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 0x4 /f
::REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0x3 /f

:: Windows DPC/ISR latencies
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d 0x1 /f

:: Nvidia gpu tweaks and latencies
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d 0x32 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d 0x1 /f

:: MMCSS
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyMode" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d 0x61A8 /f

:: GPU Scheduler low context switching (Needs testing)
:: To try: 47, 64, 57 58, 4
:: so far 47 (fps) and 64 (latency) seems best
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_SCHEDULER_MODE" /t REG_SZ /d "47" /f

:: Kernel
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /t REG_DWORD /d 0xA /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d 0x80 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /t REG_DWORD /d 0x20 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /t REG_DWORD /d 0x10000 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SplitLargeCaches" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d 0x1 /f

::SerializeTimerExpiration
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d 0x1 /f

:: DirectX Tweaks
:: D3D12AllowTiling, and D3D12HeapSerializationEnabled enabled together, can cause lighting to flicker in certain DirectX 12 games.
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /t REG_DWORD /d 0x1 /f

:: Window Manager Tweaks
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SuperWetEnabled" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SDRBoostPercentOverride" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleInLinearSpace" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OneCoreNoDWMRawGameController" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MPCInputRouterWaitForDebugger" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InteractionOutputPredictionDisabled" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InkGPUAccelOverrideVendorWhitelist" /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableRenderPathTestMode" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FlattenVirtualSurfaceEffectInput" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisallowNonDrawListRendering" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadowsRendering" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadows" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableHologramCompositor" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DebugFailFast" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DDisplayTestMode" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "UseHWDrawListEntriesOnWARP" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleModeOverride" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "RenderThreadWatchdogTimeoutMilliseconds" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ParallelModePolicy" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableMegaRects" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableFrontBufferRenderChecks" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableDesktopOverlays" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnablePrimitiveReordering" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxD3DFeatureLevel" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayQualifyCount" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayDisqualifyCount" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutModern" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutGdi" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "HighColor" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDrawListCaching" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationsShiftKey" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCommonSuperSets" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableAdvancedDirectFlip" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FrameLatency" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ForceDirectDrawSync" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxQueuedPresentBuffers" /t REG_DWORD /d 0x1 /f

:: Interrupts and Miscellaneous
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_BALANCE_POLICY" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MKL_DEBUG_CPU_TYPE" /t REG_DWORD /d 0x10 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_REQUEST_LIMIT" /t REG_DWORD /d 0x1024 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_PRIORITY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_DYNAMIC_TICK" /t REG_SZ /d "yes" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_ALLOCATION" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_LATENCY_POLICY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_PREFETCH_POLICY" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_COMPOSITOR_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_BUFFER_SIZE" /t REG_DWORD /d 0x512 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_COALESCING" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THREAD_SCHEDULER_POLICY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_INTERRUPT_MODERATION" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_COMPUTE" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_RENDER" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_BUFFER_SIZE" /t REG_DWORD /d 0x512 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f

:: Base and overtarget priorities
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}" /v "BasePriority" /t REG_DWORD /d 0xC8 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}" /v "OverTargetPriority" /t REG_DWORD /d 0x50 /f

echo.
echo Disabling Telemetry
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f 2>nul
REG ADD "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
REG ADD "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f
for %%i in (NvTmMon NvTmRep NvProfile) do for /f "tokens=1 delims=," %%a in ('schtasks /query /fo csv^| findstr /v "TaskName"^| findstr "%%~i"') do schtasks /change /tn "%%a" /disable >nul 2>&1

:: Block telemetry domains
type .\Tools\hosts > %windir%\System32\drivers\etc\hosts

::tasklist /fi "ImageName eq SetTimerResolution.exe" /fo csv 2>NUL | find /I "SetTimerResolution.exe">NUL
::echo.
::if "%ERRORLEVEL%"=="0" (
::    echo SetTimerResolution.exe is already active
::    rem echo if you wish to disable and remove it, use Restore.bat
::    goto exit
::)
::echo Do you want to set timer resolution to 0.512 and apply at startup? (Not recommended)
::set /p choiceTimerRes=Please select an option (y/N): 
::
::if "%choiceTimerRes%"=="y" goto timerResolution
::if "%choiceTimerRes%"=="Y" goto timerResolution
::if "%choiceTimerRes%"=="n" goto exit
::if "%choiceTimerRes%"=="N" goto exit
goto exit

:timerResolution
set SCRIPT="%TEMP%\%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%.vbs"

copy /Y .\Tools\SetTimerResolution.exe "C:\Windows\SetTimerResolution.exe" 1>nul 2>nul

echo Set oWS = WScript.CreateObject("WScript.Shell") >> %SCRIPT%
echo sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SetTimerResolution.exe.lnk" >> %SCRIPT%
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> %SCRIPT%
echo oLink.TargetPath = "C:\Windows\SetTimerResolution.exe" >> %SCRIPT%
echo oLink.Arguments = "--resolution 5120 --no-console" >> %SCRIPT%
echo oLink.WorkingDirectory = "C:\" >> %SCRIPT%
echo oLink.Save >> %SCRIPT%

cscript /nologo %SCRIPT%
del %SCRIPT%
start /B "" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\SetTimerResolution.exe.lnk"
echo.
goto exit

:exit
echo Restarting Explorer...
taskkill /im explorer.exe /f 1>nul 2>nul
start /B explorer.exe
echo.
echo Successfully applied all tweaks!
call Tools\colortext 0C "REBOOT REQUIRED" 1
echo Press any key to close...
pause >nul
exit


exit /b
:: Define functions here.
:bcdedit
bcdedit %* 2>nul | find /i "The operation completed successfully." >nul && echo The operation completed successfully.
exit /b