
rule TrojanDropper_AndroidOS_Hqwar_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {21 51 6e 10 ?? ?? 06 00 0a 02 12 00 34 10 08 00 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 48 03 05 00 94 04 00 02 6e 20 ?? ?? 46 00 0a 04 b7 43 8d 33 4f 03 05 00 d8 00 00 01 28 ea } //1
		$a_01_1 = {6c 6f 63 6b 4e 6f 77 } //1 lockNow
		$a_01_2 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } //1 isAdminActive
		$a_01_3 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}