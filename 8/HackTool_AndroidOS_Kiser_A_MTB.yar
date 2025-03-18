
rule HackTool_AndroidOS_Kiser_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Kiser.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {12 02 34 52 0a 00 22 00 ?? ?? 70 20 ?? ?? 10 00 11 00 d1 00 00 00 6e 10 ?? ?? 04 00 0a 03 6e 20 ?? ?? 30 00 0a 03 6e 20 ?? ?? 34 00 0a 03 50 03 01 02 d8 02 02 01 } //1
		$a_00_1 = {41 76 41 70 70 6c 69 63 61 74 69 6f 6e 73 4d 6f 6e 69 74 6f 72 } //1 AvApplicationsMonitor
		$a_00_2 = {44 61 74 61 57 69 70 65 46 6f 6c 64 65 72 73 53 74 6f 72 61 67 65 } //1 DataWipeFoldersStorage
		$a_00_3 = {53 70 61 6d 4c 69 73 74 49 74 65 6d } //1 SpamListItem
		$a_00_4 = {6c 6f 63 61 74 65 41 6e 64 53 65 6e 64 53 6d 73 } //1 locateAndSendSms
		$a_00_5 = {62 61 63 6b 75 70 5f 61 74 5f 62 6c 6f 63 6b } //1 backup_at_block
		$a_00_6 = {61 74 5f 64 65 76 69 63 65 5f 62 6c 6f 63 6b 65 64 } //1 at_device_blocked
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}