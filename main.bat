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
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 5 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------
::color B

:: Enable nvidiaProfileInspector settings
where nvidiaProfileInspector 1>nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    where choco 1>nul 2>nul
    if %ERRORLEVEL% NEQ 0 (
        PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Tools\chocolatey.ps1"
        call "Tools\RefreshEnv.cmd"
        choco feature enable -n allowGlobalConfirmation
    )
    choco install nvidia-profile-inspector -y
) else echo nvidiaProfileInspector is already installed!
nvidiaProfileInspector.exe -silentImport "%~dp0nvidiaProfileInspector\Performance.nip"
echo.

:: Disabled DMA memory protection and cores isolation
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

:: Appearance
REG add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSi /t REG_DWORD /d 0x0 /f
REG add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "10" /f
REG add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "0" /f

:: Allow Timer Resolution to be changed
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 0x1 /f

:: bypass hardware and secure boot checks
REG add "HKLM\SYSTEM\Setup\LabConfig\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 0x1 /f

:: Make startup apps load faster (May cause issues since they load before system services)
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayinMSec /t REG_DWORD /d 0x1 /f
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v WaitForIdleState /t REG_DWORD /d 0x0 /f

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

:: Old Favourites
:: 28
:: 16

:: Favourites:
:: 24/26 (Current)
:: 14/16
:: 2A/28

:: From my research it appears that no foreground boost may be better (if your system is modern)
REG add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 0x26 /f

:: Decrease mouse and keyboard buffer sizes (FOR MY SYSTEM ONLY).
REG add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0xC /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 0x10 /f

:: Disable MPO (Multi plane overlay)
REG add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /t REG_DWORD /d 0x5 /f

:: system and network tweaks
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0x0 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xA /f

:: HAGS (Hardware accelerated gpu scheduling) 2 = on, 1 = off
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 0x2 /f

:: Memory tweaks (testing LargeSystemCache = off)
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d 0x1 /f

:: Speed up HDD (IoPageLockLimit = 512kb * 100)
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v IoPageLockLimit /t REG_DWORD /d 0x51200 /f

:: Game Priority
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x8 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 0x6 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

:: Use realtime priority for csrss.exe.
::REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 0x4 /f
::REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0x3 /f

:: Windows DPC/ISR latencies
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d 0x1 /f

:: Nvidia gpu latencies
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d 0x32 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d 0x1 /f

:: Interrupts and Miscellaneous
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_BALANCE_POLICY" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MKL_DEBUG_CPU_TYPE" /t REG_DWORD /d 0x10 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_REQUEST_LIMIT" /t REG_DWORD /d 0x1024 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_PRIORITY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_DYNAMIC_TICK" /t REG_SZ /d "yes" /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_ALLOCATION" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_LATENCY_POLICY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_PREFETCH_POLICY" /t REG_DWORD /d 0x2 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_COMPOSITOR_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_BUFFER_SIZE" /t REG_DWORD /d 0x512 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_COALESCING" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THREAD_SCHEDULER_POLICY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_INTERRUPT_MODERATION" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_COMPUTE" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_RENDER" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_BUFFER_SIZE" /t REG_DWORD /d 0x512 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_IO" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_COMPLETION_POLICY" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_INTERRUPTS" /t REG_DWORD /d 0x0 /f

echo.
echo Disabling Telemetry
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f 2>nul
REG ADD "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v DisableMFUTracking /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v DeviceDumpEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInstrumentation /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInstrumentation /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /v ShowUI /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" /v ShowUI /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
REG ADD "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideRecentlyAddedApps /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v NoActiveHelp /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231 /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640 /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610 /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f
for %%i in (NvTmMon NvTmRep NvProfile) do for /f "tokens=1 delims=," %%a in ('schtasks /query /fo csv^| findstr /v "TaskName"^| findstr "%%~i"') do schtasks /change /tn "%%a" /disable >nul 2>&1

:: Block telemetry domains
type .\Tools\hosts > %windir%\System32\drivers\etc\hosts

tasklist /fi "ImageName eq SetTimerResolution.exe" /fo csv 2>NUL | find /I "SetTimerResolution.exe">NUL
echo.
if "%ERRORLEVEL%"=="0" (
    echo SetTimerResolution.exe is already active
    rem echo if you wish to disable and remove it, use Restore.bat
    goto exit
)
echo Do you want to set timer resolution to 0.512 and apply at startup?
set /p choice=Please select an option (y/N): 

if "%choice%"=="y" goto timerResolution
if "%choice%"=="Y" goto timerResolution
if "%choice%"=="n" goto exit
if "%choice%"=="N" goto exit
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