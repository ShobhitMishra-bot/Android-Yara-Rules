
rule MonitoringTool_AndroidOS_Redex_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Redex.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 49 44 45 5f 41 50 50 } //1 HIDE_APP
		$a_01_1 = {49 50 5f 4d 4f 4e 49 54 4f 52 49 4e 47 } //1 IP_MONITORING
		$a_01_2 = {48 69 64 64 65 6e 43 61 6d } //1 HiddenCam
		$a_01_3 = {48 69 64 64 65 6e 53 70 79 41 63 74 69 76 69 74 79 } //1 HiddenSpyActivity
		$a_01_4 = {75 70 6c 6f 61 64 44 65 76 69 63 65 49 6e 66 6f } //1 uploadDeviceInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}