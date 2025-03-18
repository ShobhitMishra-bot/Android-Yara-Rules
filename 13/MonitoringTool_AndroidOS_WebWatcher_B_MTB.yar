
rule MonitoringTool_AndroidOS_WebWatcher_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/WebWatcher.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 4d 6f 6e 69 74 6f 72 69 6e 67 53 65 74 75 70 41 63 74 69 76 69 74 79 } //1 AppMonitoringSetupActivity
		$a_01_1 = {63 6f 6d 2e 61 77 74 69 2e 73 6c 63 } //1 com.awti.slc
		$a_01_2 = {52 65 63 6f 72 64 65 64 44 61 74 61 } //1 RecordedData
		$a_01_3 = {57 65 62 4d 6f 6e 69 74 6f 72 69 6e 67 53 65 74 75 70 41 63 74 69 76 69 74 79 } //1 WebMonitoringSetupActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}