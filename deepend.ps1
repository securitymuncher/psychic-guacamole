<#
.SYNOPSIS
Windows CCDC First 5 Minutes Script
.DESCRIPTION
This script is designed to be used in the CCDC challenge to apply baseline
security and network hardening while also generating data files for the competition.
.EXAMPLE
PS> .\deepend.ps1
Will write all the results out to the screen and the default file of first5-date-machinename.txt
.EXAMPLE
PS> .\deepend.ps1 -OutputFileName UniqueFileNameHere.txt
Will write the results out to the current directory under the specified filename.
.LINK
https://github.com/thenamol/psychic-guacamole
#>
[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $OutputFileName = ""
)
#To do list:
#Functions needed
#generate secure passwords
function get-strongpwd {
$basepwd = "DirtyBirdsAtNight"
$date = get-date -format yyyy-mm-dd
$objRand = new-object random
$num = $objRand.next(1,500)
$finalPWD = $basepwd + "!" + $date + "!" + $num
$finalPWD
}
#Get local users and document them
function get-lusers {
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $namey = $_.name
        if ($null = $groups) {
            $groups = "N/A"
        }
        $namey 
 }
}
# Create new local Admin user for script purposes
function add-backupadmin {

$Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
$passwd = get-strongpwd
$LocalAdmin = $Computer.Create("User", "WGU-Admin")
$LocalAdmin.SetPassword($passwd)
$LocalAdmin.SetInfo()
$LocalAdmin.FullName = "Nightowls Secured Account"
$LocalAdmin.SetInfo()
# ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
$LocalAdmin.UserFlags = 64 + 65536
$LocalAdmin.SetInfo()
}

#add backup admin
Write-Output "Adding backup administrator account"
add-backupadmin
#get list of users
Write-Output "Generating list of local users"
$users = get-lusers

#change passwords
Write-Output "Attempting to change user passwors"
foreach ($user in $users) {
    try {
        $plainTextPWD = get-strongpwd
        Write-Output "Setting $user to $plainTextPWD"
        $securePWD = ConvertTo-SecureString -String $plainTextPWD -AsPlainText -Force
        set-localuser -name $user -Password $securePWD
        Write-Output "$user,$securePWD" >> $env:COMPUTERNAME-localusers.txt
    }
    catch {
        Write-Output "Failure when trying to change a local user password!"
        Write-Output "User: $user"
    }
}

#configure windows firewall
# Netsh.exe advfirewall firewall add rule name="Block Notepad.exe network connections" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe network connections" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block calc.exe network connections" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block mshta.exe network connections" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block wscript.exe network connections" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block cscript.exe network connections" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe network connections" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
# Netsh.exe Advfirewall set allprofiles state on
#Powershell version
Write-Output "Adding outbound rules to prevent LOLBins."
#add rules to prevent lolbins outbound
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-Notepad.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\notepad.exe' }
New-NetFirewallRule @params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-regsvr32.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\regsvr32.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-calc.exe' 
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\calc.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-mshta.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\mshta.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-wscript.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\wscript.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-cscript.exe' 
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\cscript.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-runscripthelper.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\runscripthelper.exe' }
New-NetFirewallRule @Params
$Params = @{ "DisplayName" = 'WGU-Block Network Connections-regsvr32.exe'
             "Direction" = 'Outbound'
             "Action" = 'Block'
             "Program" = '%systemroot%\system32\regsvr32.exe' }
New-NetFirewallRule @Params

#add rules to filter inbound
#Commented out just to be used as a reference
# $Params = @{ "DisplayName" = 'WGY-Block-Inbound-SMB-445'
#              "Direction" = 'Inbound'
#              "Port" = '445'}
# New-NetFirewallRule @Params

#enable firewall
$Params = @{ "Profile" = 'Domain,Public,Private'
             "Enabled" = 'true'
             "defaultInboundAction" = 'Block'
             "LogAllowed" = 'True'
             "LogBlocked" = 'True'
             "LogIgnored" = 'True'
             "LogFileName" = '%windir%\system32\logfiles\firewall\pfirewall.log'
             "LogMaxSizeKilobytes" = '32767'

}
Set-NetFirewallProfile @Params
# Set-NetFirewallProfile -Profile Domain,Public,Private `
#                        -Enabled True `
#                        -DefaultInboundAction Block `
#                        -LogAllowed True `
#                        -LogBlocked True `
#                        -LogFileName %windir%\system32\logfiles\firewall\pfirewall.log `
#                        -LogMaxSizeKilobytes 32767

#Baseline security hardening
#disable smbv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

#disable smbv2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force

#Enable smb encryption for 2012r2 or higher
Set-SmbServerConfiguration –EncryptData $true

#Disable SMB null sessions
Write-Output "Disabling SMB null sessions."
$registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$Params = @{ "Path" = 'HKLM:\System\CurrentControlSet\Control\Lsa'
             "Name" = 'RestrictAnonymous'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
$Params = @{ "Path" = 'HKLM:\System\CurrentControlSet\Control\Lsa'
             "Name" = 'RestrictAnonymousSAM'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
$Params = @{ "Path" = 'HKLM:\System\CurrentControlSet\Control\Lsa'
             "Name" = 'EveryoneIncludesAnonymous'
             "Value" = "0"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}

#Disable llmnr to prevent bad times
Write-Output "Disabling LLMNR"
#REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
#REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
$registryPath = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
$Params = @{ "Path" = 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient'
             "Name" = 'EnableMulticast'
             "Value" = "0"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}

#Harden LSA to protect from mimikatz etc
#reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
Write-Output "Enabling protections for LSA"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$Params = @{ "Path" = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
             "Name" = 'AuditLevel'
             "Value" = "8"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Params = @{ "Path" = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
             "Name" = 'RunAsPPL'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$Params = @{ "Path" = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
             "Name" = 'UseLogonCredential'
             "Value" = "0"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
$Params = @{ "Path" = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
             "Name" = 'AllowProtectedCreds'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
#disable netbios over tcp/ip and lmhosts lookups
$nics = Get-WmiObject win32_NetworkAdapterConfiguration
foreach ($nic in $nics){
        $nic.settcpipnetbios(2) # 2 = disable netbios on interface
        $nic.enablewins($false,$false) #disable wins
    }
#enable powershell logging
Write-Output "Enabling powershell logging"
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$Params = @{ "Path" = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
             "Name" = 'EnableModuleLogging'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$Params = @{ "Path" = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
             "Name" = 'EnableModuleLogging'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}
#reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$Params = @{ "Path" = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
             "Name" = 'ProcessCreationIncludeCmdLine_Enabled'
             "Value" = "1"
             "PropertyType" = 'DWORD'
}
if(!(Test-Path $registryPath))  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty $params -Force | Out-Null
}
else {
    New-ItemProperty $params -Force | Out-Null
}

#Bump windows event log size
Write-Output "Increasing the Windows Event Log Size to 1.5GB"
$Logs = Get-Eventlog -List | Select-Object -ExpandProperty Log
Limit-Eventlog -Logname $Logs -MaximumSize 1.5Gb -OverflowAction OverwriteAsNeeded

#Disable SMB Compression
#https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
Write-Output "Disabling SMB Compression for CVE 2020-0796"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name "DisableCompression" -Type DWORD -Value 1 -Force