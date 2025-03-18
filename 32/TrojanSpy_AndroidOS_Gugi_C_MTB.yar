
rule TrojanSpy_AndroidOS_Gugi_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gugi.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 67 6f 6f 67 69 65 2f 73 79 73 74 65 6d } //1 com/googie/system
		$a_01_1 = {73 65 74 53 74 61 74 75 73 4f 6b 54 61 73 6b } //1 setStatusOkTask
		$a_01_2 = {73 61 76 65 53 6d 73 53 65 72 76 65 72 } //1 saveSmsServer
		$a_01_3 = {72 65 74 75 72 6e 53 6d 73 4c 69 73 74 54 69 64 } //1 returnSmsListTid
		$a_01_4 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 } //1 sendContacts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}