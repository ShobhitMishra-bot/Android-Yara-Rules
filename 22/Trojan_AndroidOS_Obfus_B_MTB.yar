
rule Trojan_AndroidOS_Obfus_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Obfus.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 70 32 00 00 00 00 00 71 20 ?? ?? 04 00 00 00 00 00 0a 07 00 00 00 00 71 10 ?? ?? 01 00 00 00 00 00 0a 08 00 00 00 00 94 08 00 08 00 00 00 00 71 20 ?? ?? 81 00 00 00 00 00 0a 08 00 00 00 00 b7 87 00 00 00 00 8e 77 00 00 00 00 71 20 ?? ?? 76 00 00 00 00 00 d8 00 00 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}