
rule TrojanSpy_AndroidOS_Cerberus_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cerberus.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {21 70 23 00 a9 00 12 01 21 72 35 21 34 00 52 62 ?? 00 d8 02 02 01 d4 22 00 01 59 62 ?? 00 52 62 ?? 00 54 63 ?? 00 52 64 ?? 00 44 05 03 04 b0 52 d4 22 00 01 59 62 ?? 00 52 62 ?? 00 71 30 ?? ?? 24 03 54 62 ?? 00 52 63 ?? 00 44 03 02 03 52 64 ?? 00 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 4f 02 00 01 d8 01 01 01 28 cc 11 00 } //2
		$a_00_1 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //1 send_log_injects
		$a_00_2 = {6f 70 65 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 openAccessibilityService
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}