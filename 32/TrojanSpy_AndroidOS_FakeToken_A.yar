
rule TrojanSpy_AndroidOS_FakeToken_A{
	meta:
		description = "TrojanSpy:AndroidOS/FakeToken.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 54 6f 53 65 72 76 65 72 } //1 sendContactsToServer
		$a_01_1 = {4c 74 6f 6b 65 6e 2f 62 6f 74 2f 41 75 74 6f 72 75 6e 52 65 63 65 69 76 65 72 } //1 Ltoken/bot/AutorunReceiver
		$a_01_2 = {4c 74 6f 6b 65 6e 2f 62 6f 74 2f 53 65 6e 64 53 6d 73 52 65 73 75 6c 74 } //1 Ltoken/bot/SendSmsResult
		$a_01_3 = {4c 74 6f 6b 65 6e 2f 62 6f 74 2f 53 65 72 76 65 72 52 65 73 70 6f 6e 73 65 } //1 Ltoken/bot/ServerResponse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}