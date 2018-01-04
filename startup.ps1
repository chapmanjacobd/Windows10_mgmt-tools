$COMPUTER = "localhost"
$NAMESPACE = "root\standardcimv2\embedded"

$CommonParams = @{"namespace"=$NAMESPACE; "computer"=$COMPUTER}

# Make sure that UWF is currently disabled

  $UWFFilter = Get-WmiObject -class UWF_Filter @commonParams

  if ($UWFFilter.CurrentEnabled -eq $false) {
  
  & "reg" load 'HKLM\tempuser' "C:\Users\config\ntuser.dat"
  & "reg" add "HKLM\tempuser\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Windows\System32\oobe\info\backgrounds\green.jpg /f
  & "reg" unload 'HKLM\tempuser'
  & "rundll32.exe" user32.dll, UpdatePerUserSystemParameters,1,true

	# INSTALL SPECIAL
	if (Test-Path C:\Users\config\Desktop\ARMED) {
		if (!(Test-Path C:\Users\config\Desktop\postimage\installed)) {
			& C:\Users\config\Desktop\postimage\install.ps1
			msg * "Done post-image install"
		}
	}

    # true: run windows update, ninite
    Set-Service wuauserv -StartupType manual
    Start-Service wuauserv
    Set-Service WSearch -StartupType manual
    Start-Service WSearch
    
    & "C:\Users\config\Desktop\utils\Ninite.exe"
    sleep -s 100
    
	##(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    Install-WindowsUpdate -IgnoreReboot -MicrosoftUpdate -AcceptAll -Severity Critical
	
	# or maybe try "p 5850K"
	& "C:\Users\config\Desktop\utils\display\ClickMonitorDDC.exe" b 50 c 75 r 255 g 250 l 242 m	
    
    # disable windows update
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\" -Name "Start" -Type DWord -Value 4
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch\" -Name "Start" -Type DWord -Value 4
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "Start_TrackProgs" -Type DWord -Value 0
	
    # update java_home env variable
    
    $jdkDp = (Get-ChildItem -Path "C:\Program Files\Java\jdk*" | Sort-Object name | Select-Object -Last 1).FullName
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name JAVA_HOME -Value $jdkDp
	
	# enable write filter
    if (!(Test-Path C:\Users\config\Desktop\noreboot)) {
      Start-Process -Wait -NoNewWindow uwfmgr -ArgumentList 'filter enable'
	}
	
    Start-Process -Wait -NoNewWindow uwfmgr -ArgumentList 'volume protect c:'
    Start-Process -Wait -NoNewWindow uwfmgr -ArgumentList 'overlay set-Size 12288'
    Start-Process -Wait -NoNewWindow uwfmgr -ArgumentList 'overlay Set-WarningThreshold 7680'
    Start-Process -Wait -NoNewWindow uwfmgr -ArgumentList 'overlay Set-CriticalThreshold 10960'
    Start-Process -Wait -NoNewWindow wmic -ArgumentList 'pagefileset where name="C:\\pagefile.sys" set InitialSize=16284,MaximumSize=16284'
	
		& "uwfmgr" File add-exclusion "c:\Windows\ccmcache"
		& "uwfmgr" File add-exclusion "c:\_TaskSequence"
		& "uwfmgr" file add-exclusion "C:\Data\Programdata\softwaredistribution"
		& "uwfmgr" file add-exclusion "C:\Data\SharedData\DuShared"
		& "uwfmgr" file add-exclusion "C:\Data\SystemData\temp"
		& "uwfmgr" file add-exclusion "C:\Data\Users\System\AppData\Local\UpdateStagingRoot"
		& "uwfmgr" file add-exclusion "C:\Data\systemdata\nonetwlogs"
		& "uwfmgr" file add-exclusion "C:\Data\users\defaultaccount\appdata\local\temp"
		& "uwfmgr" file add-exclusion "C:\Program Files\Windows Defender"
		& "uwfmgr" file add-exclusion "C:\ProgramData\Microsoft\Network\Downloader"
		& "uwfmgr" file add-exclusion "C:\ProgramData\Microsoft\Windows Defender"
		& "uwfmgr" file add-exclusion "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft System Center"
		& "uwfmgr" file add-exclusion "C:\ProgramData\Microsoft\dot3svc\Profiles\Interfaces"
		& "uwfmgr" file add-exclusion "C:\ProgramData\Microsoft\wlansvc\Profiles\Interfaces"
		& "uwfmgr" file add-exclusion "C:\ProgramFiles(X86)\Windows Defender"
		& "uwfmgr" file add-exclusion "C:\Windows\Temp\MpCmdRun.log"
		& "uwfmgr" file add-exclusion "C:\Windows\WindowsUpdate.log"
		& "uwfmgr" file add-exclusion "C:\Windows\dot2svc\Policies"
		& "uwfmgr" file add-exclusion "C:\Windows\wlansvc\Policies"
		& "uwfmgr" file add-exclusion "c:\ProgramData\Microsoft\Crypto"
		& "uwfmgr" file add-exclusion "c:\Windows\System32\Microsoft\Protect"
		& "uwfmgr" file add-exclusion "c:\_TaskSequence"
		& "uwfmgr" file add-exclusion "c:\windows\System32\Winevt\Logs"
		& "uwfmgr" file add-exclusion "c:\windows\ccm"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\CcmStore.sdf"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\CertEnrollmentStore.sdf"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\InventoryStore.sdf"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\ServiceData"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\StateMessageStore.sdf"
		& "uwfmgr" file add-exclusion "c:\windows\ccm\UserAffinityStore.sdf"
		& "uwfmgr" file add-exclusion "c:\windows\ccmcache"
		& "uwfmgr" file add-exclusion "c:\windows\ccmssetup"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Antimalware"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM\StateSystem"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WiredL2\GP_Policy"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wlansvc"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WwanSvc"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dot3svc"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\Software\Microsoft\SystemCertificates\SMS\Certificates"
		& "uwfmgr" registry add-exclusion "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\BITS\StateIndex"
		
		& "uwfmgr" file add-exclusion "C:\Users\Student\VirtualBox VMs\CentOS"
		& "uwfmgr" file add-exclusion "C:\Users\Student\VirtualBox VMs\CentOS\CentOS.vdi"

	Remove-Item C:\Users\config\Desktop\* -include *.lnk
    Remove-Item C:\Users\Student\Desktop\* -include *.lnk
    Remove-Item C:\Users\Public\Desktop\* -include *.lnk
	
	sleep -s 10
	
	# cleanup
	    
    & "C:\Users\config\Desktop\utils\NirSoft\nircmd.exe" emptybin
    & "C:\Users\config\Desktop\utils\NirSoft\nircmd.exe" mutesysvolume 1
	& "C:\Users\config\Desktop\utils\wsname.exe" /PG:DEFAULT /N:'$DNS:10.10.224.68' /NOREBOOT
    sleep -s 10
	& "C:\Users\config\Desktop\utils\display\ClickMonitorDDC.exe" q
	
	if (Test-Path C:\Users\config\Desktop\NOREBOOT) {
		msg * "Done startup"
	}
	
	if (!(Test-Path C:\Users\config\Desktop\NOREBOOT)) {
		New-Item -ItemType file C:\Users\config\Desktop\postimage\installed
		& "shutdown.exe" -r -t 1800
		msg * "System Shutdown in 30mins! Run shutdown /a to abort!!"
	}
 } else {
  & "reg" load 'HKLM\tempuser' "C:\Users\config\ntuser.dat"
  & "reg" add "HKLM\tempuser\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Windows\System32\oobe\info\backgrounds\red.jpg /f
  & "reg" unload 'HKLM\tempuser'
  & "rundll32.exe" user32.dll, UpdatePerUserSystemParameters,1,true
}
