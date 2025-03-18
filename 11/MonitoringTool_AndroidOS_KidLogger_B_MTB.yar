
rule MonitoringTool_AndroidOS_KidLogger_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/KidLogger.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 2e 6b 64 6c 2e 74 61 6c 6b 62 61 63 6b 74 73 } //2 net.kdl.talkbackts
		$a_00_1 = {54 61 6b 65 45 78 74 72 61 6f 72 64 69 6e 61 72 79 53 63 72 65 65 6e 73 68 6f 74 } //1 TakeExtraordinaryScreenshot
		$a_00_2 = {53 65 6e 64 55 72 6c 54 6f 4c 6f 67 } //1 SendUrlToLog
		$a_00_3 = {62 6c 6f 63 6b 41 70 70 } //1 blockApp
		$a_00_4 = {44 65 73 63 72 5f 6f 72 5f 55 52 4c } //1 Descr_or_URL
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}