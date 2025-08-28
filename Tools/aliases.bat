@echo off
cls
rem disbale UAC (temp): SET __COMPAT_LAYER=WINXPSP3

DOSKEY vi=nvim $*
DOSKEY super=ss -n -l $*
DOSKEY main=ss -o -n $*
DOSKEY commit=git commit $*
DOSKEY grep=findstr $1 $2
DOSKEY ls=dir /D $*
DOSKEY l=dir /B $*
DOSKEY ll=dir /A $*
DOSKEY pwd=cd
DOSKEY ps=tasklist
DOSKEY clear=cls
DOSKEY cat=type $*
DOSKEY youtube=start brave "youtube.com"
DOSKEY vcpkgdir=cd /D "C:\vcpkg"
DOSKEY nvimdir=cd /D "%USERPROFILE%\AppData\Local\nvim"
DOSKEY alacrittydir=cd /D "%USERPROFILE%\AppData\Roaming\alacritty"
DOSKEY home=cd /D "%USERPROFILE%"
DOSKEY desk=cd /D "%USERPROFILE%\Desktop"
DOSKEY D:=cd /D "D:\"
DOSKEY E:=cd /D "E:\"
DOSKEY C:=cd /D "C:\"
DOSKEY dev=cd /D "%USERPROFILE%\dev"
DOSKEY extdir=cd /D "%USERPROFILE%\dev\External"
DOSKEY pydir=cd /D "%USERPROFILE%\dev\Python"
DOSKEY rustdir=cd /D "%USERPROFILE%\dev\Rust"
DOSKEY cppdir=cd /D "%USERPROFILE%\dev\C++"
DOSKEY csdir=cd /D "%USERPROFILE%\dev\C#"
DOSKEY webdir=cd /D "%USERPROFILE%\dev\Website"

rem DOSKEY sai2="%USERPROFILE%\Desktop\Paint Tool Sai 2\sai2_x64\sai2.exe"
rem DOSKEY sai2_32="%USERPROFILE%\Desktop\Paint Tool Sai 2\sai2_x86\sai2.exe"