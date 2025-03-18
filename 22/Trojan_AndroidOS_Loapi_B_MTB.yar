
rule Trojan_AndroidOS_Loapi_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Loapi.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 31 2c 00 48 03 0b 01 6e 10 ?? ?? 02 00 0b 04 84 44 48 04 0c 04 b7 43 8d 33 4f 03 00 01 6e 10 ?? ?? 02 00 0b 04 16 06 01 00 bb 64 71 20 ?? ?? 54 00 0c 02 6e 10 ?? ?? 02 00 0b 04 21 c3 81 36 31 03 04 06 3a 03 07 00 22 02 12 00 70 30 ?? ?? 82 09 d8 01 01 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}