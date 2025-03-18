
rule MonitoringTool_AndroidOS_Cerberus_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cerberus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 65 72 62 65 72 75 73 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 67 65 74 64 65 76 69 63 65 73 2e 70 68 70 } //1 cerberusapp.com/api/getdevices.php
		$a_01_1 = {53 45 4e 44 5f 53 4d 53 5f 52 45 53 55 4c 54 } //1 SEND_SMS_RESULT
		$a_01_2 = {63 65 72 62 65 72 75 73 } //1 cerberus
		$a_01_3 = {63 6f 6d 2f 6c 73 64 72 6f 69 64 2f 63 65 72 62 65 72 75 73 } //1 com/lsdroid/cerberus
		$a_01_4 = {67 65 74 64 65 76 69 63 65 73 74 61 74 75 73 2e 70 68 70 } //1 getdevicestatus.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}