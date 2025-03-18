
rule Trojan_AndroidOS_SpyAgent_G{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 74 73 6d 73 6f 6e 65 } //2 lastsmsone
		$a_01_1 = {66 75 6c 6c 69 6e 66 6f 6f 6e 65 } //2 fullinfoone
		$a_01_2 = {63 6f 6d 2e 65 78 63 65 70 74 69 6f 6e 2e 72 61 74 } //2 com.exception.rat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}