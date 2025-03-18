
rule Trojan_AndroidOS_GriftHorse_G_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 00 14 03 ?? ?? 0c 7f 6e 20 ?? ?? 32 00 14 03 ?? ?? 09 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 5b 23 ?? ?? 6e 10 ?? ?? 03 00 0c 03 12 10 6e 20 2e 15 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 03 54 20 ?? ?? 71 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 71 10 ?? ?? 02 00 0c 01 6e 20 ?? ?? 10 00 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 03 00 } //10
		$a_03_1 = {0c 00 12 11 6e 20 ?? ?? 10 00 54 30 ?? ?? 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 20 ?? ?? 31 00 6e 20 ?? ?? 10 00 6e 10 ?? ?? 03 00 0c 00 54 31 ?? ?? 71 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 54 32 ?? ?? 71 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 } //10
		$a_03_2 = {70 73 3a 2f 2f 64 [0-20] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-35] 2e 68 74 6d 6c 3f } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=15
 
}