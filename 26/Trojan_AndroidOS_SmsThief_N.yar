
rule Trojan_AndroidOS_SmsThief_N{
	meta:
		description = "Trojan:AndroidOS/SmsThief.N,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 61 78 5f 53 6d 73 5f 54 69 6d 65 } //2 Max_Sms_Time
		$a_00_1 = {67 65 74 58 6d 73 55 73 65 72 } //2 getXmsUser
		$a_00_2 = {58 6d 73 41 70 69 } //2 XmsApi
		$a_00_3 = {4b 45 59 5f 4c 41 53 54 5f 53 4d 53 5f 4b 45 59 } //2 KEY_LAST_SMS_KEY
		$a_00_4 = {58 6d 73 53 65 72 76 69 63 65 2e 69 73 52 75 6e 6e 69 6e 67 3a } //2 XmsService.isRunning:
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}