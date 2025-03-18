
rule TrojanSpy_AndroidOS_Svpeng_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 69 74 6c 65 72 5f 62 61 63 6b 6d 79 62 65 77 69 6c 6c 63 68 61 6e 67 65 64 73 6f 6f 6e } //1 hitler_backmybewillchangedsoon
		$a_00_1 = {73 74 61 72 74 70 6c 65 61 73 65 32 } //1 startplease2
		$a_00_2 = {79 6e 6f 74 5f 62 75 74 74 6f 6e } //1 ynot_button
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanSpy_AndroidOS_Svpeng_B_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 67 66 62 6b 6e 69 6f 73 65 } //1 kgfbkniose
		$a_01_1 = {69 6e 6a 65 63 74 73 6c 69 73 74 } //1 injectslist
		$a_01_2 = {64 65 66 73 6d 73 } //1 defsms
		$a_01_3 = {73 74 61 72 74 5f 73 6d 73 5f 67 72 61 62 } //1 start_sms_grab
		$a_01_4 = {62 74 74 64 6c 72 76 61 76 65 } //1 bttdlrvave
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}