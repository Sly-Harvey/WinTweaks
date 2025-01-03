@echo off
:: BatchGotAdmin
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

title Temporary Data Cleaner
echo ================================================
echo This Tool will delete any sort of Temporary Data
echo from your PC, which are slowing it down.
echo ================================================
echo.
echo 1. Clean Temp Files
echo 2. Close Tool
echo.
set /p choice=Please select an option (1-2): 

if "%choice%"=="1" goto clean
if "%choice%"=="2" goto exit
goto invalid

:clean
echo Cleaning temporary files...
echo.

REM Deleting Windows temporary files
del /s /q %temp%\*.* 2>nul
rd /s /q %temp% 2>nul

REM Deleting Windows prefetch files
del /s /q C:\Windows\Prefetch\*.* 2>nul

REM Deleting Windows temp files
del /s /q C:\Windows\Temp\*.* 2>nul
rd /s /q C:\Windows\Temp 2>nul

REM Deleting user temporary files
del /s /q "%userprofile%\AppData\Local\Temp\*.*" 2>nul
rd /s /q "%userprofile%\AppData\Local\Temp" 2>nul

REM Deleting temporary internet files
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8

echo Temporary files cleaned successfully.
pause
goto exit

:exit
exit

:invalid
echo Invalid choice. Please select option 1 or 2.
pause
cls
goto start
