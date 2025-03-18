
rule TrojanSpy_AndroidOS_Xanomorph_A{
	meta:
		description = "TrojanSpy:AndroidOS/Xanomorph.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 63 63 65 73 73 52 61 69 6e 62 6f 77 53 65 72 76 65 72 3a 20 73 65 6e 64 20 6d 65 73 73 61 67 65 } //2 accessRainbowServer: send message
		$a_01_1 = {49 44 79 6e 61 6d 69 63 4c 6f 61 64 65 72 } //2 IDynamicLoader
		$a_01_2 = {63 68 65 63 6b 41 76 61 69 6c 61 62 69 6c 69 74 79 3a 20 73 74 61 72 74 20 74 6f 20 61 63 63 65 73 73 20 63 6f 6e 66 69 67 20 73 65 72 76 65 72 } //2 checkAvailability: start to access config server
		$a_01_3 = {70 65 6e 61 6c 74 79 72 69 76 65 72 } //1 penaltyriver
		$a_01_4 = {74 77 65 6c 76 65 6d 61 72 72 69 61 67 65 } //1 twelvemarriage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}