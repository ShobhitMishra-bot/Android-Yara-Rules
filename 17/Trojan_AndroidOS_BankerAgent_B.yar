
rule Trojan_AndroidOS_BankerAgent_B{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 65 67 74 74 73 73 } //2 foregttss
		$a_01_1 = {63 72 65 79 45 4e 56 49 41 73 4d 53 } //2 creyENVIAsMS
		$a_01_2 = {63 6f 6e 74 61 64 6f 72 53 65 6e 64 73 53 4d } //2 contadorSendsSM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}