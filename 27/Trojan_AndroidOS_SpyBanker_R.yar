
rule Trojan_AndroidOS_SpyBanker_R{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.R,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4e 61 74 69 6f 6e 61 6c 43 6f 64 65 2e 70 68 70 } //2 sendNationalCode.php
		$a_01_1 = {2f 6d 65 6c 6c 61 74 2f 4c 41 63 74 69 76 69 74 79 } //2 /mellat/LActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}