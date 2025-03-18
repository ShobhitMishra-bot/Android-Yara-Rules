
rule TrojanSpy_AndroidOS_Ubsod_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ubsod.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 62 30 65 73 64 2e 72 75 } //1 mob0esd.ru
		$a_00_1 = {61 70 73 39 30 74 65 6c 2e 72 75 } //1 aps90tel.ru
		$a_00_2 = {6d 6f 62 31 6c 69 68 65 6c 70 2e 72 75 } //1 mob1lihelp.ru
		$a_00_3 = {64 65 6c 61 79 2e 66 75 6c 6c 73 63 72 65 65 6e } //1 delay.fullscreen
		$a_00_4 = {73 63 72 65 65 6e 20 6c 6f 63 6b 65 64 } //1 screen locked
		$a_00_5 = {61 64 6d 69 6e 44 69 73 61 62 6c 65 64 } //1 adminDisabled
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}