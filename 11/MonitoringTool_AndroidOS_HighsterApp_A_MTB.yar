
rule MonitoringTool_AndroidOS_HighsterApp_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/HighsterApp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {65 76 74 31 37 2e 63 6f 6d 2f 69 70 68 6f 6e 65 2f 6e 65 77 5f 61 6e 64 72 6f 69 64 5f 73 65 72 76 69 63 65 73 } //1 evt17.com/iphone/new_android_services
		$a_00_1 = {68 69 67 68 73 74 65 72 } //1 highster
		$a_00_2 = {70 61 74 53 70 79 32 32 2e 64 62 } //1 patSpy22.db
		$a_00_3 = {4c 6f 72 67 2f 73 65 63 75 72 65 2f 73 6d 73 67 70 73 2f 48 69 67 68 73 74 65 72 41 70 70 } //1 Lorg/secure/smsgps/HighsterApp
		$a_00_4 = {4c 6f 72 67 2f 73 75 66 66 69 63 69 65 6e 74 6c 79 73 65 63 75 72 65 2f 72 6f 6f 74 63 6f 6d 6d 61 6e 64 73 } //1 Lorg/sufficientlysecure/rootcommands
		$a_00_5 = {67 65 74 4c 61 74 65 73 74 43 61 6c 6c 73 } //1 getLatestCalls
		$a_00_6 = {67 65 74 4c 61 74 65 73 74 53 6d 73 } //1 getLatestSms
		$a_00_7 = {67 65 74 57 68 61 74 73 61 70 70 45 61 72 6c 69 65 73 74 4d 73 67 49 64 } //1 getWhatsappEarliestMsgId
		$a_00_8 = {64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } //1 doInBackground
		$a_00_9 = {4c 6f 72 67 2f 73 65 63 75 72 65 2f 73 6d 73 67 70 73 2f 74 61 73 6b 2f 64 61 69 6c 79 } //1 Lorg/secure/smsgps/task/daily
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}