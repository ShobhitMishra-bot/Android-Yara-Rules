
rule MonitoringTool_AndroidOS_SAgnt_F_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 6b 2e 68 61 73 61 6e 6b 61 73 73 65 6d 2e 73 69 6d 63 68 61 6e 67 65 64 } //1 tk.hasankassem.simchanged
		$a_01_1 = {4d 79 44 65 76 69 63 65 41 64 6d 69 6e 52 65 63 65 69 76 65 72 } //1 MyDeviceAdminReceiver
		$a_01_2 = {6d 4c 61 73 74 4c 6f 63 61 74 69 6f 6e } //1 mLastLocation
		$a_01_3 = {4c 6f 73 74 4f 66 66 6c 69 6e 65 50 72 6f } //5 LostOfflinePro
		$a_01_4 = {74 6b 2e 68 61 73 61 6e 6b 61 73 73 65 6d } //5 tk.hasankassem
		$a_01_5 = {61 63 74 69 76 69 74 79 5f 66 6f 72 67 6f 74 } //1 activity_forgot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1) >=13
 
}