
rule Trojan_AndroidOS_KeyLogger_A{
	meta:
		description = "Trojan:AndroidOS/KeyLogger.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 70 61 6c 79 73 6d 75 64 69 63 } //1 _palysmudic
		$a_01_1 = {66 69 6c 69 6e 66 6f 64 61 74 } //1 filinfodat
		$a_01_2 = {69 73 41 63 63 65 73 73 53 65 72 76 69 63 65 45 6e 61 62 6c 65 64 } //1 isAccessServiceEnabled
		$a_01_3 = {4c 61 69 72 61 2f 76 61 74 2f } //1 Laira/vat/
		$a_01_4 = {5f 70 68 69 64 61 74 73 75 } //1 _phidatsu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}