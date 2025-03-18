
rule MonitoringTool_AndroidOS_Letmespy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Letmespy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 20 4f 55 54 } //1 SMS OUT
		$a_01_1 = {69 73 43 6f 6c 6c 65 63 74 50 68 6f 6e 65 } //1 isCollectPhone
		$a_01_2 = {6c 6f 61 64 50 68 6f 6e 65 73 44 6f } //1 loadPhonesDo
		$a_01_3 = {63 68 65 63 6b 43 6f 6c 6c 65 63 74 50 68 6f 6e 65 54 61 73 6b } //1 checkCollectPhoneTask
		$a_01_4 = {6c 6f 67 43 61 6c 6c 4c 6f 67 } //1 logCallLog
		$a_01_5 = {70 6c 2e 6c 69 64 77 69 6e 2e 6c 65 74 6d 65 73 70 79 } //1 pl.lidwin.letmespy
		$a_01_6 = {69 63 6f 6e 48 69 64 65 } //1 iconHide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}