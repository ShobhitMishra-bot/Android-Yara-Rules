
rule MonitoringTool_AndroidOS_MonitorMinor_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MonitorMinor.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 6f 53 4d 53 52 65 63 65 76 69 65 72 } //1 AutoSMSRecevier
		$a_00_1 = {41 43 54 49 4f 4e 5f 53 45 4e 44 5f 53 4d 53 5f 52 4f 55 4e 44 } //1 ACTION_SEND_SMS_ROUND
		$a_00_2 = {73 74 61 72 74 20 73 65 6e 64 20 74 68 65 20 61 75 74 6f 20 73 6d 73 } //1 start send the auto sms
		$a_00_3 = {74 68 69 73 20 72 6f 75 6e 64 20 68 61 73 20 73 65 6e 64 20 73 6d 73 20 63 6f 75 6e 74 } //1 this round has send sms count
		$a_00_4 = {46 61 6b 65 4c 61 6e 75 63 68 65 72 41 63 74 69 76 69 74 79 } //1 FakeLanucherActivity
		$a_00_5 = {72 65 63 65 69 76 65 20 61 20 6e 65 77 20 63 61 6c 6c 20 66 6f 72 } //1 receive a new call for
		$a_00_6 = {6d 6d 73 63 2e 6d 6f 6e 74 65 72 6e 65 74 2e 63 6f 6d } //1 mmsc.monternet.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}