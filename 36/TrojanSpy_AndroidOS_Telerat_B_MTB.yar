
rule TrojanSpy_AndroidOS_Telerat_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Telerat.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6d 73 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SmsInterceptor
		$a_00_1 = {4c 69 73 74 65 6e 54 6f 4f 75 74 67 6f 69 6e 67 4d 65 73 73 61 67 65 73 } //1 ListenToOutgoingMessages
		$a_00_2 = {69 6e 63 6f 6d 69 6e 67 5f 6e 75 6d 62 65 72 } //1 incoming_number
		$a_00_3 = {61 70 69 2e 72 61 79 61 6e 6f 6f 73 2e 69 72 2f 62 6f 74 } //1 api.rayanoos.ir/bot
		$a_00_4 = {61 6c 6c 73 6d 73 2e 7a 69 70 } //1 allsms.zip
		$a_00_5 = {77 77 77 2e 73 75 6e 70 61 78 2e 67 61 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 www.sunpax.ga/upload.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}