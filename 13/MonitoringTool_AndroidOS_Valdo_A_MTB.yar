
rule MonitoringTool_AndroidOS_Valdo_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Valdo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 61 6b 65 53 6f 63 6b 65 74 46 61 63 74 6f 72 79 } //1 FakeSocketFactory
		$a_01_1 = {53 65 6e 64 50 69 63 41 73 79 6e 63 } //1 SendPicAsync
		$a_00_2 = {63 6f 6d 2e 76 6c 61 64 6f 2e 70 72 6f 74 6f 74 79 70 65 } //5 com.vlado.prototype
		$a_01_3 = {6c 61 73 74 43 6f 6e 74 61 63 74 44 61 74 65 } //1 lastContactDate
		$a_00_4 = {63 6f 6d 2e 73 79 73 74 65 6d 2e 67 70 73 2e 74 6f 6f 6c 73 2e 6d 6d 6d 6f 6e 6e 6e 69 74 6f 72 2f 64 61 74 61 62 61 73 65 73 2f 70 72 6f 74 6f 2e 64 62 } //5 com.system.gps.tools.mmmonnnitor/databases/proto.db
		$a_01_5 = {65 78 74 72 61 63 74 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //1 extractBrowserHistory
		$a_01_6 = {65 78 74 72 61 63 74 57 41 6d 73 67 } //1 extractWAmsg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*5+(#a_01_3  & 1)*1+(#a_00_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=14
 
}