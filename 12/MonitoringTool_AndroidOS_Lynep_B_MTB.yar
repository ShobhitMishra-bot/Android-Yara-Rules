
rule MonitoringTool_AndroidOS_Lynep_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Lynep.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 6b 70 68 6f 6e 65 2e 6d 6f 62 69 } //1 trackphone.mobi
		$a_01_1 = {67 65 74 53 4d 53 48 69 73 74 6f 72 79 } //1 getSMSHistory
		$a_01_2 = {74 72 61 63 6b 5f 70 68 6f 6e 75 6d 62 65 72 } //1 track_phonumber
		$a_01_3 = {63 61 6c 6c 73 2e 64 62 } //1 calls.db
		$a_01_4 = {74 72 63 61 6b 5f 63 61 6c 6c 5f 64 75 72 61 74 69 6f 6e } //1 trcak_call_duration
		$a_01_5 = {2f 73 6d 61 72 74 5f 70 68 70 2f 73 74 61 74 73 2e 70 68 70 } //1 /smart_php/stats.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}