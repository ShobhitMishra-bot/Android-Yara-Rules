
rule MonitoringTool_AndroidOS_NeoSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/NeoSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 68 6f 6e 65 43 61 6c 6c 4c 65 6e 67 74 68 54 72 61 63 6b 65 72 } //1 PhoneCallLengthTracker
		$a_00_1 = {63 68 65 63 6b 41 6e 64 52 65 69 6e 73 74 61 6c 6c 41 6c 61 72 6d 73 } //1 checkAndReinstallAlarms
		$a_00_2 = {53 65 6e 64 41 70 70 73 } //1 SendApps
		$a_00_3 = {53 65 6e 64 4b 65 79 73 74 72 6f 6b 65 73 } //1 SendKeystrokes
		$a_00_4 = {53 65 6e 64 53 6d 73 } //1 SendSms
		$a_00_5 = {6e 73 2e 61 6e 74 61 70 70 2e 6d 6f 64 75 6c 65 } //1 ns.antapp.module
		$a_01_6 = {6e 65 6f 73 70 79 } //1 neospy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}