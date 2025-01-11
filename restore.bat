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

REG DELETE "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f 2>nul
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSi" /f 2>nul
REG ADD "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f
REG ADD "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "1" /f

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d 0x0 /f

REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /f 2>nul

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2 /f

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /f 2>nul

REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 0x64 /f
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /f 2>nul

REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d 0x64 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d 0x5 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d 0xA /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d 0x5 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d 0x28 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d 0x32 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d 0x10 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d 0x168 /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000156e000000000000000000000000004001000000000029dc03000000000000000000280000000000 /f
REG ADD "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000fd11010000000000002404000000000000fc12000000000000000000c0bb01000000000000 /f

::REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0x14 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xA /f

REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /f 2>nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0x3 /f
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /f 2>nul

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "Normal" /f

REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /f 2>nul

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /f 2>nul

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /f 2>nul

REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d 0x4 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 0x0 /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyMode" /f 2>nul
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d 0x0 /f

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_SCHEDULER_MODE" /f 2>nul

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d 0x2710 /f
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SplitLargeCaches" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /f 2>nul

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /f 2>nul

REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /f 2>nul

REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FrameLatency" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ForceDirectDrawSync" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxQueuedPresentBuffers" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SuperWetEnabled" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "SDRBoostPercentOverride" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleInLinearSpace" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OneCoreNoDWMRawGameController" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MPCInputRouterWaitForDebugger" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InteractionOutputPredictionDisabled" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "InkGPUAccelOverrideVendorWhitelist" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableRenderPathTestMode" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "FlattenVirtualSurfaceEffectInput" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisallowNonDrawListRendering" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadowsRendering" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableProjectedShadows" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableHologramCompositor" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DebugFailFast" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DDisplayTestMode" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableLockingMemory" /f 2>nul
REG ADD "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d 1 /f
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "UseHWDrawListEntriesOnWARP" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResampleModeOverride" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "RenderThreadWatchdogTimeoutMilliseconds" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ParallelModePolicy" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableMegaRects" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableFrontBufferRenderChecks" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableDesktopOverlays" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnablePrimitiveReordering" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "MaxD3DFeatureLevel" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayQualifyCount" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "OverlayDisqualifyCount" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutModern" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "ResizeTimeoutGdi" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableResizeOptimization" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableEffectCaching" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "HighColor" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDeviceBitmaps" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCpuClipping" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableDrawListCaching" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "AnimationsShiftKey" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "EnableCommonSuperSets" /f 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\WINDOWS\DWM" /v "DisableAdvancedDirectFlip" /f 2>nul

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_INTERRUPT_BALANCE_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MKL_DEBUG_CPU_TYPE" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_COMPLETION_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_REQUEST_LIMIT" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_PRIORITY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISK_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "IO_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_THROTTLE_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWER_IDLE_TIMEOUT" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CPU_POWER_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DISABLE_DYNAMIC_TICK" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_ALLOCATION" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_LATENCY_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_PREFETCH_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "MEMORY_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DWM_COMPOSITOR_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_BUFFER_SIZE" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_INTERRUPT_COALESCING" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TIMER_RESOLUTION" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "THREAD_SCHEDULER_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_INTERRUPT_MODERATION" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "NETWORK_ADAPTER_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_COMPLETION_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "STORAGE_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "USB_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "PCIE_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_COMPUTE" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_MAX_PENDING_RENDER" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_BUFFER_SIZE" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "AUDIO_DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_PENDING_INTERRUPTS" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_IO" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_COMPLETION_POLICY" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "DEVICE_MAX_PENDING_INTERRUPTS" /f 2>nul

REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}" /v "BasePriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0003" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0002" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0001" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Video\{33123269-1807-11EF-B26D-806E6F6E6963}\0000" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f8ecafa6-66d1-41a5-899b-66585d7216b7}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f3586baf-b5aa-49b5-8d6c-0569284c639f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f048e777-b971-404b-bd9c-3802613495c2}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{eec5ad98-8080-425f-922a-dabf3de3f69a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e55fa6f9-128c-4d04-abab-630c74b1453a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e2f84ce7-8efa-411c-aa69-97454ca4cb57}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d546500a-2aeb-45f6-9482-f4b1799c3177}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d421b08e-6d16-41ca-9c4d-9147e5ac98e0}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{d02bc3da-0c8e-4945-9bd5-f1883c226c8c}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ce5939ae-ebde-11d0-b181-0000f8753ec4}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cdcf0939-b75b-4630-bf76-80f7ba655884}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{cc342e67-bd5b-4dd2-bb7b-bf23cf9f2a0e}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{c06ff265-ae09-48f0-812c-16753d7cba83}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{bbbe8734-08fa-4966-b6a6-4e5ad010cdd7}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b2728d24-ac56-42db-9e02-8edaf5db652f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{b1d1a169-c54f-4379-81db-bee7d88d7454}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a73c93f1-9727-4d1d-ace1-0e333ba4e7db}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a3e32dba-ba89-4f17-8386-2d0127fbd4cc}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a701c0-a511-42ff-aa6c-06dc0395576f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8ecc055d-047f-11d1-a537-0000f8753ed1}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{89786ff1-9c12-402f-9c9e-17753c7f4375}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88bae032-5a81-49f0-bc3d-a4ff138216d6}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{88a1c342-4539-11d3-b88d-00c04fad5171}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{8503c911-a6c7-4919-8f79-5028f5866b0c}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{72631e54-78a4-11d0-bcf7-00aa00b7b32a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71aa14f8-6fad-4622-ad77-92bb9d7e6947}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6fae73b7-b735-4b50-a0da-0dc2484b1f1a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6d807884-7d21-11cf-801c-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc5-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc1-810f-11d0-bec7-08002be2092f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{62f9c741-b25a-46ce-b54c-9bccce08b6f2}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5d1b9aaa-01e2-46af-849f-272b3f324c46}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5c4c3332-344d-483c-8739-259e934c9cc8}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5989fce8-9cd0-467d-8a6a-5419e31529d4}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5630831c-06c9-4856-b327-f5d32586e060}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53d29ef7-377c-4d14-864b-eb3a85769359}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53ccb149-e543-4c84-b6e0-bce4f6b7e806}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53b3cf03-8f5a-4788-91b6-d19ed9fcccbf}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53966cb1-4d46-4166-bf23-c522403cd495}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{53487c23-680f-4585-acc3-1f10d6777e82}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{533c5b84-ec70-11d2-9505-00c04f79deaf}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5175d334-c371-4806-b3ba-71fd53c9258d}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{5099944a-f6b9-4057-a056-8c550228544c}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50906cb8-ba12-11d1-bf5d-0000f805f530}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{50127dc3-0f36-415e-a6cc-4cb3be910b65}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97e-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e978-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e977-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e973-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e971-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e970-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96e-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96d-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96a-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e966-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e965-e325-11ce-bfc1-08002be10318}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{48721b56-6795-11d2-b1a8-0080c72e74a2}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4658ee7e-f050-11d1-b6bd-00c04fa372a7}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{43675d81-502a-4a82-9f84-b75f418c5dea}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{3e3f0674-c83c-4558-bb26-9820e1eba5c5}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{2db15374-706e-4131-a0c7-d7c78eb0289a}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{268c95a1-edfe-11d3-95c3-0010dc4050a5}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{14b62f50-3f15-11dd-ae16-0800200c9a66}" /v "OverTargetPriority" /f 2>nul
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Class\{1264760f-a5c8-4bfe-b314-d56a7b44a362}" /v "OverTargetPriority" /f 2>nul

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