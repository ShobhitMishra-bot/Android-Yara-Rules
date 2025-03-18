
rule MonitoringTool_AndroidOS_Ikeymon_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Ikeymon.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 49 4d 49 54 5f 53 43 52 45 45 4e 5f 53 48 4f 54 53 } //1 LIMIT_SCREEN_SHOTS
		$a_01_1 = {43 6f 6d 6d 61 6e 4d 65 74 68 6f 64 } //1 CommanMethod
		$a_01_2 = {73 65 6e 64 41 6c 6c 43 61 6c 6c 48 69 73 74 6f 72 79 } //1 sendAllCallHistory
		$a_01_3 = {67 65 74 49 73 57 65 62 4c 6f 67 73 } //1 getIsWebLogs
		$a_01_4 = {67 65 74 49 73 53 4d 53 4c 6f 67 } //1 getIsSMSLog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}