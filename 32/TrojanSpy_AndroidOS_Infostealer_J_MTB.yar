
rule TrojanSpy_AndroidOS_Infostealer_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Infostealer.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 getAllContacts
		$a_01_1 = {57 6f 72 6b 4e 6f 77 } //1 WorkNow
		$a_01_2 = {73 68 6f 77 43 6f 6e 74 61 63 74 73 } //1 showContacts
		$a_01_3 = {6d 73 67 42 6f 64 79 } //1 msgBody
		$a_01_4 = {69 73 4d 6f 62 69 6c 65 4e 4f } //1 isMobileNO
		$a_01_5 = {70 6f 73 74 44 61 74 61 } //1 postData
		$a_01_6 = {67 65 74 4c 69 73 74 } //1 getList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}