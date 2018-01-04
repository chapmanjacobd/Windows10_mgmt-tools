if (!(Test-Path C:\Users\config\Desktop\postimage\installed)) {


cscript c:\windows\system32\slmgr.vbs -ato

# nslookup -type=srv _vlmcs._tcp

cscript "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /act

msg * "Windows / Office activated"

& 'C:\Users\config\Desktop\postimage\cctk_update.exe'

msg * "BIOS Settings Set"

# install printer, lanschool based on reverse DNS name
#Author: Nam Seobin
#get DNS information
$allInfo = [System.Net.Dns]::GetHostByName(($env:computerName))
#get AddressList and then convert it to string
$ipAddress = $allInfo.AddressList[0].IPAddressToString

$ip = $ipAddress.Split(".")

If ($ip[2] -eq 101) {
msg * "GCB101 Detected! Installing Printers..."
	$lanschoolchannel = 101
	& "C:\Users\config\Desktop\postimage\printers\GCB101_for_x64.exe" -quiet
}
#172.123.111.*
ElseIf ($ip[2] -eq 111) {
msg * "GCB111 Detected! Installing Printers..."
	$lanschoolchannel = 111
	& "C:\Users\config\Desktop\postimage\printers\GCB111_for_x64.exe" -quiet
msg * "Installing SAP Crystal Reports..."
	& 'C:\Users\config\Desktop\postimage\SAP\Crystal.Reports.2016\DATA_UNITS\CrystalReports\setup.exe' -r C:\Users\config\Desktop\postimage\SAP\sapresponse.crystalr.ini
msg * "Installing SAP Dashboards..."
	& 'C:\Users\config\Desktop\postimage\SAP\SAP.Dashboards.2016\DATA_UNITS\Xcelsius\setup.exe' -r C:\Users\config\Desktop\postimage\SAP\sapresponse.dashboards.ini
msg * "Installing SAP Lumira..."
	& 'C:\Users\config\Desktop\postimage\SAP\lumira\setup.exe' -r C:\Users\config\Desktop\postimage\SAP\sapresponse.lumira.ini
	Copy-Item C:\Users\config\Desktop\postimage\SAP\saplogin.ini C:\Users\config\AppData\Roaming\SAP\LogonServerConfigCache
	Copy-Item C:\Users\config\Desktop\postimage\SAP\saplogin.ini C:\Users\Student\AppData\Roaming\SAP\Common
}
#172.123.140.*
ElseIf ($ip[2] -eq 140) {
	$lanschoolchannel = 140
	& "C:\Users\config\Desktop\postimage\printers\GCB140_for_x64.exe" -quiet
}
#Teacher
If ($ip[3] -eq 100) {
msg * "Installing LanSchool Teacher..."
	& "msiexec.exe" /i C:\Users\config\Desktop\postimage\LanSchool\Teacher.msi /qn REBOOT=ReallySuppress ADVANCED_OPTIONS=1 SECURE_MODE=1 PASSWORD=cislai3 PASSWORD_CONFIRM=cislai3 CHANNEL=$lanschoolchannel NO_REBOOT=1
}
#Student
ElseIf ($ip[3] -ge 101 -and $ip[3] -le 255) {
msg * "Installing LanSchool Student..."
	& "msiexec.exe" /i C:\Users\config\Desktop\postimage\LanSchool\Student.msi /qn REBOOT=ReallySuppress ADVANCED_OPTIONS=1 SECURE_MODE=1 PASSWORD=cislai3 PASSWORD_CONFIRM=cislai3 CHANNEL=$lanschoolchannel NO_REBOOT=1
}
Else {
	'Dude!'
}


}
