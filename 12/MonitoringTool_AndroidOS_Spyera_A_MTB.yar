
rule MonitoringTool_AndroidOS_Spyera_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyera.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 45 4e 44 5f 4e 55 4d 42 45 52 } //1 SEND_NUMBER
		$a_00_1 = {63 6f 6e 74 61 63 74 49 6e 66 6f } //1 contactInfo
		$a_00_2 = {63 61 6c 6c 73 4f 62 73 65 72 76 65 72 } //1 callsObserver
		$a_00_3 = {55 70 6c 6f 61 64 4d 73 67 53 65 72 76 69 63 65 } //1 UploadMsgService
		$a_00_4 = {75 70 6c 6f 61 64 50 68 6f 74 6f 73 } //1 uploadPhotos
		$a_00_5 = {72 75 6e 6e 69 6e 67 41 70 70 50 72 6f 63 65 73 73 49 6e 66 6f 73 } //1 runningAppProcessInfos
		$a_00_6 = {53 50 59 20 3d } //1 SPY =
		$a_00_7 = {55 50 4c 4f 41 44 5f 41 43 54 49 56 45 5f 55 52 4c } //1 UPLOAD_ACTIVE_URL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}