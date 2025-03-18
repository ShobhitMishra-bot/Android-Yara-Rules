
rule Trojan_AndroidOS_SmsBot_A{
	meta:
		description = "Trojan:AndroidOS/SmsBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 65 6d 6f 76 65 41 6c 6c 53 6d 73 41 6e 73 77 65 72 73 } //1 RemoveAllSmsAnswers
		$a_00_1 = {73 74 61 72 74 42 61 63 6b 67 72 6f 75 6e 64 53 6d 73 28 29 } //1 startBackgroundSms()
		$a_00_2 = {4c 64 65 6c 65 74 65 2f 6f 66 66 2f 41 64 6d 69 6e 52 65 63 65 69 76 65 72 3b } //1 Ldelete/off/AdminReceiver;
		$a_00_3 = {53 49 50 4d 4c 45 5f 50 48 4f 4e 45 5f 41 4e 44 5f 54 45 58 54 } //1 SIPMLE_PHONE_AND_TEXT
		$a_00_4 = {69 73 46 69 73 72 74 28 29 3a 20 74 72 75 65 } //1 isFisrt(): true
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_AndroidOS_SmsBot_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {2a 2a 20 53 65 72 76 69 63 65 20 28 66 75 6c 6c 73 6d 73 5f } //1 ** Service (fullsms_
		$a_00_1 = {2a 2a 20 53 65 72 76 69 63 65 20 28 69 6e 73 74 61 6c 6c 5f } //1 ** Service (install_
		$a_00_2 = {2a 2a 20 53 65 72 76 69 63 65 20 28 73 6d 73 5f } //1 ** Service (sms_
		$a_02_3 = {0c 02 23 73 [0-04] e2 04 00 18 8d 44 4f 04 03 01 e2 04 00 10 8d 44 4f 04 03 06 e2 04 00 08 8d 44 4f 04 03 08 8d 00 4f 00 03 09 4d 03 02 09 01 12 35 72 2f 00 01 10 54 a3 [0-04] 21 33 35 30 1e 00 54 a3 [0-04] 48 04 03 00 71 00 [0-04] 00 00 0c 05 46 05 05 02 71 00 [0-04] 00 00 0c 06 46 06 06 02 21 66 94 06 00 06 48 05 05 06 b7 54 8d 44 4f 04 03 00 d8 00 00 01 28 e0 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=12
 
}