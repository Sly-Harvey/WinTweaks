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

call :bcdedit /deletevalue firstmegabytepolicy
call :bcdedit /deletevalue avoidlowmemory
call :bcdedit /deletevalue nolowmem

call :bcdedit /deletevalue vsmlaunchtype

call :bcdedit /deletevalue x2apicpolicy
call :bcdedit /deletevalue configaccesspolicy

call :bcdedit /deletevalue useplatformclock
call :bcdedit /deletevalue useplatformtick
call :bcdedit /deletevalue disabledynamictick
call :bcdedit /deletevalue tscsyncpolicy

REG delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f 2>nul
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSi" /f 2>nul
REG add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f
REG add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "1" /f

REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d 0x0 /f

REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /f 2>nul

REG add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2 /f

REG add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 0x64 /f
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /f 2>nul

::REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 0x1 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0x14 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xA /f

REG delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /f 2>nul
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 0x0 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0x3 /f
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /f 2>nul

REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x2 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 0x2 /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "Normal" /f

REG delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /f 2>nul

REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /f 2>nul

REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /f 2>nul

REG add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d 0x2710 /f
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SplitLargeCaches" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /f 2>nul

REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /f 2>nul

REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FrameLatency" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ForceDirectDrawSync" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxQueuedPresentBuffers" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SuperWetEnabled" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SDRBoostPercentOverride" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleInLinearSpace" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OneCoreNoDWMRawGameController" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MPCInputRouterWaitForDebugger" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InteractionOutputPredictionDisabled" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InkGPUAccelOverrideVendorWhitelist" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableRenderPathTestMode" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FlattenVirtualSurfaceEffectInput" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisallowNonDrawListRendering" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadowsRendering" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadows" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableHologramCompositor" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DebugFailFast" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DDisplayTestMode" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /f 2>nul
REG add "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d 1 /f
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "UseHWDrawListEntriesOnWARP" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleModeOverride" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "RenderThreadWatchdogTimeoutMilliseconds" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ParallelModePolicy" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableMegaRects" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableFrontBufferRenderChecks" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableDesktopOverlays" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnablePrimitiveReordering" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxD3DFeatureLevel" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayQualifyCount" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayDisqualifyCount" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutModern" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutGdi" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "HighColor" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDrawListCaching" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationsShiftKey" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCommonSuperSets" /f 2>nul
REG delete "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableAdvancedDirectFlip" /f 2>nul

REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_BALANCE_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MKL_DEBUG_CPU_TYPE" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_COMPLETION_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_REQUEST_LIMIT" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_PRIORITY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_THROTTLE_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_IDLE_TIMEOUT" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_POWER_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_DYNAMIC_TICK" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_ALLOCATION" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_LATENCY_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_PREFETCH_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_COMPOSITOR_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_BUFFER_SIZE" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_COALESCING" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THREAD_SCHEDULER_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_INTERRUPT_MODERATION" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_COMPLETION_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_COMPUTE" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_RENDER" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_BUFFER_SIZE" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_IO" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_COMPLETION_POLICY" /f 2>nul
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul

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