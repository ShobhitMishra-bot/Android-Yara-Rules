
rule MonitoringTool_AndroidOS_MobiStealth_AS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobiStealth.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 74 68 57 69 70 65 53 4d 53 50 72 6f 63 65 73 73 6f 72 } //1 StealthWipeSMSProcessor
		$a_00_1 = {6d 6f 62 69 73 74 65 61 6c 74 68 } //1 mobistealth
		$a_01_2 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 } //1 CallRecording
		$a_00_3 = {63 61 6c 6c 6c 6f 67 2e 64 61 74 } //1 calllog.dat
		$a_00_4 = {63 61 6c 6c 20 69 73 20 72 69 6e 67 69 6e 67 } //1 call is ringing
		$a_00_5 = {70 68 6f 6e 65 77 69 70 65 69 6e 66 6f 2e 64 61 74 } //1 phonewipeinfo.dat
		$a_00_6 = {41 6c 6c 20 44 61 74 61 20 6f 6e 20 70 68 6f 6e 65 20 68 61 73 20 62 65 65 6e 20 77 69 70 65 64 20 6f 75 74 } //1 All Data on phone has been wiped out
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}