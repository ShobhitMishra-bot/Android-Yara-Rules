
rule Trojan_AndroidOS_GriftHorse_O_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {4c 63 6f 6d 2f [0-57] 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //1
		$a_00_1 = {2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //1 .cloudfront.net
		$a_02_2 = {21 00 71 00 [0-04] 00 00 0c 02 6e 20 [0-04] 12 00 0c 02 6e 10 [0-04] 01 00 0c 00 6e 20 [0-04] 02 00 0c 02 54 10 [0-04] 6e 20 [0-04] 02 00 0c 02 54 10 [0-04] 6e 20 [0-04] 02 00 0c 02 54 10 [0-04] 6e 20 [0-04] 02 00 0c 02 6e 20 [0-04] 12 00 6e 10 [0-04] 01 00 } //1
		$a_00_3 = {67 65 74 43 6f 6e 74 65 6e 74 52 65 73 6f 6c 76 65 72 } //1 getContentResolver
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}