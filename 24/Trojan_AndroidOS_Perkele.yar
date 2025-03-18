
rule Trojan_AndroidOS_Perkele{
	meta:
		description = "Trojan:AndroidOS/Perkele,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 73 74 61 72 74 5f 73 72 76 00 } //1 敲瑳牡彴牳v
		$a_01_1 = {6d 79 6c 6f 67 5f 6d 65 73 73 00 } //1
		$a_01_2 = {6d 79 6c 6f 67 5f 6e 65 65 64 00 } //1
		$a_01_3 = {53 4d 53 20 53 45 4e 44 20 45 52 52 4f 52 3a 20 4e 4f 20 54 45 58 54 2e 00 } //1
		$a_01_4 = {6e 65 77 4b 65 79 67 75 61 72 64 4c 6f 63 6b 00 } //1 敮䭷祥畧牡䱤捯k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}