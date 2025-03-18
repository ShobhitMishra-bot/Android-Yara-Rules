
rule TrojanSpy_AndroidOS_SmsThief_BC_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 72 65 6d 6f 74 65 61 70 70 } //2 com.example.remoteapp
		$a_01_1 = {74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 36 } //1 telegram.org/bot6
		$a_01_2 = {65 78 74 72 61 63 74 4d 65 73 73 61 67 65 73 } //1 extractMessages
		$a_01_3 = {53 4d 53 52 65 63 65 69 76 65 72 2e 6b 74 } //1 SMSReceiver.kt
		$a_01_4 = {52 61 74 4d 61 69 6e } //1 RatMain
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}