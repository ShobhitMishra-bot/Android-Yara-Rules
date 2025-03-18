
rule Trojan_AndroidOS_Mobtes_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Mobtes.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 6e 5f 73 73 6c } //1 dn_ssl
		$a_00_1 = {62 69 6e 64 52 65 61 6c 41 70 70 6c 69 63 61 74 69 6f 6e } //1 bindRealApplication
		$a_00_2 = {67 65 74 4c 65 61 73 74 43 6f 69 6e 73 } //1 getLeastCoins
		$a_00_3 = {6c 6f 61 64 58 46 69 6c 65 } //1 loadXFile
		$a_00_4 = {64 65 63 72 79 70 74 } //1 decrypt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}