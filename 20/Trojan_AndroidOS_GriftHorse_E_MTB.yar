
rule Trojan_AndroidOS_GriftHorse_E_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 75 6b 6a 30 74 35 71 34 63 65 31 75 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //1 dukj0t5q4ce1u.cloudfront.net
		$a_00_1 = {63 6f 6d 2f 76 69 64 78 2f 76 69 64 65 6f 73 71 75 65 78 2f 61 63 74 69 76 69 74 69 65 73 } //1 com/vidx/videosquex/activities
		$a_00_2 = {67 65 74 49 73 50 72 65 6d 69 75 6d } //1 getIsPremium
		$a_00_3 = {52 76 5f 43 6c 69 63 6b 6c 69 73 74 65 72 6e 65 72 } //1 Rv_Clicklisterner
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}