
rule Trojan_AndroidOS_Ermac_U{
	meta:
		description = "Trojan:AndroidOS/Ermac.U,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 69 6e 6a 65 63 74 61 6e 64 6c 69 73 74 61 70 70 73 } //1 updateinjectandlistapps
		$a_01_1 = {74 65 78 74 32 7a 7a 7a } //1 text2zzz
		$a_01_2 = {75 70 64 61 74 65 42 6f 74 50 61 72 61 6d 73 6c } //1 updateBotParamsl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}