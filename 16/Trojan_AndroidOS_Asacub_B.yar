
rule Trojan_AndroidOS_Asacub_B{
	meta:
		description = "Trojan:AndroidOS/Asacub.B,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 20 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db df f8 ?? ?? 00 21 7a 44 12 68 53 5c ?? 33 53 54 8b 1c 01 31 83 42 f8 d1 df f8 ?? ?? 00 20 79 44 09 68 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db df f8 ?? ?? 00 21 7a 44 12 68 53 5c ?? 33 53 54 8b 1c 01 31 83 42 f8 d1 df f8 ?? ?? 00 20 79 44 09 68 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db } //2
		$a_01_1 = {03 af 4d f8 04 8d 04 46 13 48 90 46 22 68 78 44 05 68 20 46 92 69 55 f8 21 10 90 47 06 46 20 68 55 f8 28 20 31 46 d5 f8 e4 36 d0 f8 40 52 20 46 a8 47 02 46 20 68 31 46 d0 f8 58 32 20 46 98 47 05 46 20 68 31 46 c2 6d 20 46 90 47 28 46 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}