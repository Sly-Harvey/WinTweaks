# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
function n { notepad $args }

# Set up command prompt and window title. Use UNIX-style convention for identifying.
#function prompt { 
#    if ($isAdmin) {
#        "[" + (Get-Location) + "] # " 
#    } else {
#        "[" + (Get-Location) + "] $ "
#    }
#}

# Display powershell version in window title.
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
  if ($args.Count -gt 0) {   
      $argList = "& '" + $args + "'"
      Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
  } else {
      Start-Process "$psHome\powershell.exe" -Verb runAs
  }
}

Remove-Variable identity
Remove-Variable principal

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
  if ($args.Count -gt 0) {
      Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
  } else {
      Get-ChildItem -Recurse | Foreach-Object FullName
  }
}

#function ll { Get-ChildItem -Path $pwd -File }
function vi { nvim $args}
function gcom {
  git add .
  git commit -m "$args"
}
function lazyg {
  git add .
  git commit -m "$args"
  git push
}
function Get-PubIP {
  (Invoke-WebRequest http://ifconfig.me/ip ).Content
}
function reload-profile {
  & $profile
}
function find-file($name) {
  Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
      $place_path = $_.directory
      Write-Output "${place_path}\${_}"
  }
}
function unzip ($file) {
  Write-Output("Extracting", $file, "to", $pwd)
  $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
  Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function ix ($file) {
  curl.exe -F "f:1=@$file" ix.io
}
function grep($regex, $dir) {
  if ( $dir ) {
      Get-ChildItem $dir | select-string $regex
      return
  }
  $input | select-string $regex
}
function touch($file) {
  "" | Out-File $file -Encoding ASCII
}
function df {
  get-volume
}
function sed($file, $find, $replace) {
  (Get-Content $file).replace("$find", $replace) | Set-Content $file
}
function which($name) {
  Get-Command $name | Select-Object -ExpandProperty Definition
}
function export($name, $value) {
  set-item -force -path "env:$name" -value $value;
}
function pkill($name) {
  Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}
function pgrep($name) {
  Get-Process $name
}

Set-Alias -Name ff -Value find-file
#Set-Alias -Name su -Value admin
#Set-Alias -Name sudo -Value admin
Set-Alias -Name ll -Value dir

function super { ss -n -l $args }
function main { ss -o -n $args }
function commit { git commit $args }
function youtube { start brave "youtube.com" }
function vcpkgdir { cd -Path "C:\vcpkg" }
function nvimdir { cd -Path "$env:USERPROFILE\AppData\Local\nvim" }
function alacrittydir { cd -Path "$env:USERPROFILE\AppData\Roaming\alacritty" }
function home { cd -Path "$env:USERPROFILE" }
function desk { cd -Path "$env:USERPROFILE\Desktop" }
function D: { cd -Path "D:\" }
function E: { cd -Path "E:\" }
function C: { cd -Path "C:\" }
function dev { cd -Path "$env:USERPROFILE\dev" }
function extdir { cd -Path "$env:USERPROFILE\dev\External" }
function pydir { cd -Path "$env:USERPROFILE\dev\Python" }
function rustdir { cd -Path "$env:USERPROFILE\dev\Rust" }
function cppdir { cd -Path "$env:USERPROFILE\dev\C++" }
function csdir { cd -Path "$env:USERPROFILE\dev\C#" }
function webdir { cd -Path "$env:USERPROFILE\dev\Website" }
function artdir { cd -Path "$env:USERPROFILE\Art" }
function refimgdir { cd -Path "$env:USERPROFILE\Art\Reference Images" }

# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
