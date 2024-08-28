@echo off
setlocal EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "DEL=%%a"
)>nul
goto :file
:text

echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1
goto :eof
:file
set help=%1
if %help%== help goto help
call :text %1 %2
set ec=%3
if %ec%== 1 echo.
exit /b
:help
echo colortext [atr] ["text"] [line]
echo.
echo Color attributes are specified by TWO hex digits -- the first
echo corresponds to the background; the second the foreground.  Each digit
echo can be any of the following values:
echo.
echo    0 = Black       8 = Gray
echo    1 = Blue        9 = Light Blue
echo    2 = Green       A = Light Green
echo    3 = Aqua        B = Light Aqua
echo    4 = Red         C = Light Red
echo    5 = Purple      D = Light Purple
echo    6 = Yellow      E = Light Yellow
echo    7 = White       F = Bright White
echo.
echo 0 - No ending line.
echo 1 - Ending the line.
echo.
pause