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

reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 0x1 /f

reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 0x1 /f
reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 0x1 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSi /t REG_DWORD /d 0x0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xA /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0x0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0xC /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 0x10 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0x8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 0x6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "10" /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "0" /f

:: All values are in hex format
:: Fixed = lower input latency and consistent
:: Variable = higher fps but inconsistent (Try this if your cpu gets hot)
:: Short = better input latency
:: Long = better fps
:: FG (Forground Boost) = Prioritize forground apps that have focus.
:: FG isn't good for input latency but it's good for fps and smooth.

:: Short-Fixed values: 28, 2A (FG)
:: Short-Variable values: 24, 26 (FG)
:: Long-Variable values: 14, 16 (FG)

:: Suggestions: 
:: 28 (Low input latency)
:: 16 (Higher fps and Smooth)
:: Guide: https://www.xbitlabs.com/win32priorityseparation-performance/
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 0x2A /f

tasklist /fi "ImageName eq SetTimerResolution.exe" /fo csv 2>NUL | find /I "SetTimerResolution.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo.
    echo SetTimerResolution.exe is already active
    rem echo if you wish to disable and remove it, use Restore.bat
    goto exit
)
echo Do you want to set timer resolution to 0.512 and apply at startup?
set /p choice=Please select an option (Y/n): 

if "%choice%"=="y" goto timerResolution
if "%choice%"=="Y" goto timerResolution
if "%choice%"=="n" goto exit
if "%choice%"=="N" goto exit
goto timerResolution

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