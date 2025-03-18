
rule TrojanSpy_AndroidOS_SmsSpy_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 68 6f 6e 65 32 2f 73 74 6f 70 2f 61 63 74 69 76 69 74 79 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/phone2/stop/activity/MainActivity
		$a_01_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 31 30 30 } //1 content://sms/100
		$a_01_2 = {68 61 73 5f 73 65 6e 64 5f 70 68 6f 6e 65 5f 69 6e 66 6f } //1 has_send_phone_info
		$a_01_3 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_01_4 = {68 61 73 5f 73 65 6e 64 5f 63 6f 6e 74 61 63 74 73 } //1 has_send_contacts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}