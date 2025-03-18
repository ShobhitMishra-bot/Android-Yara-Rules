
rule TrojanSpy_AndroidOS_Realrat_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 73 65 72 76 69 63 65 5f 42 52 } //1 hideservice_BR
		$a_01_1 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 getAllContacts
		$a_01_2 = {43 6f 6e 74 61 63 74 73 32 57 72 61 70 70 65 72 } //1 Contacts2Wrapper
		$a_01_3 = {67 65 74 41 6c 6c 43 61 6c 6c 73 } //1 getAllCalls
		$a_01_4 = {53 6d 73 57 72 61 70 70 65 72 } //1 SmsWrapper
		$a_01_5 = {66 61 6b 65 6d 61 69 6e } //1 fakemain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanSpy_AndroidOS_Realrat_I_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 6d 75 6c 74 69 70 61 72 74 74 65 78 74 6d 65 73 73 61 67 65 } //1 sendmultiparttextmessage
		$a_00_1 = {64 69 64 20 79 6f 75 20 66 6f 72 67 65 74 20 74 6f 20 63 61 6c 6c 20 61 63 74 69 76 69 74 79 } //1 did you forget to call activity
		$a_00_2 = {2f 72 65 63 65 69 76 65 2e 70 68 70 } //1 /receive.php
		$a_00_3 = {67 65 74 63 6f 6e 74 61 63 74 73 } //1 getcontacts
		$a_00_4 = {68 69 64 65 69 63 6f 6e } //1 hideicon
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}