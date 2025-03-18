
rule MonitoringTool_AndroidOS_SpyPhone_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyPhone.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 69 64 65 49 63 6f 6e 73 } //1 HideIcons
		$a_00_1 = {73 69 76 61 72 74 65 63 68 2e 63 6f 6d 2f 73 70 79 70 68 6f 6e 65 2f 74 75 74 6f 72 69 61 6c } //1 sivartech.com/spyphone/tutorial
		$a_00_2 = {48 69 64 65 4d 65 64 69 61 } //1 HideMedia
		$a_00_3 = {53 70 79 50 68 6f 6e 65 41 63 74 69 76 69 74 79 } //1 SpyPhoneActivity
		$a_00_4 = {73 74 61 72 74 56 69 64 65 6f 52 65 63 6f 72 64 69 6e 67 } //1 startVideoRecording
		$a_00_5 = {73 69 76 61 72 74 65 63 68 2f 73 70 79 70 68 6f 6e 65 2f 53 70 79 50 68 6f 6e 65 41 70 70 6c 69 63 61 74 69 6f 6e } //1 sivartech/spyphone/SpyPhoneApplication
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}