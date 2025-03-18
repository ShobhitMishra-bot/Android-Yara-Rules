
rule TrojanSpy_AndroidOS_SMSSpy_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 4d 6f 6e 69 74 6f 72 } //1 CallMonitor
		$a_01_1 = {42 4f 54 5f 54 4f 4b 45 4e } //1 BOT_TOKEN
		$a_01_2 = {53 4d 53 4d 6f 6e 69 74 6f 72 } //1 SMSMonitor
		$a_01_3 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 } //1 /sendMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}