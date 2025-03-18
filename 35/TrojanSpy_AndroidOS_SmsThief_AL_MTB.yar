
rule TrojanSpy_AndroidOS_SmsThief_AL_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 4f 42 53 65 72 76 65 72 } //1 SMSOBServer
		$a_01_1 = {73 6e 65 64 43 6f 6e 74 61 63 74 73 } //1 snedContacts
		$a_01_2 = {42 61 64 53 4d 53 52 65 63 65 69 76 65 72 } //1 BadSMSReceiver
		$a_01_3 = {42 41 4e 4b 5f 54 4f 50 5f 43 48 45 43 4b 5f 54 49 4d 45 } //1 BANK_TOP_CHECK_TIME
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_SmsThief_AL_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //1 getSmsInPhone
		$a_01_1 = {50 4f 53 54 5f 43 4f 4e 54 41 43 54 } //1 POST_CONTACT
		$a_01_2 = {53 4d 53 5f 55 52 49 5f 41 4c 4c } //1 SMS_URI_ALL
		$a_01_3 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 getAllContacts
		$a_01_4 = {70 68 6f 6e 65 2f 74 72 61 6e 73 66 65 72 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 phone/transfer/receiver/SmsReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}