
rule Trojan_AndroidOS_FoncySms_A{
	meta:
		description = "Trojan:AndroidOS/FoncySms.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6e 6f 74 20 72 65 67 69 73 74 72 65 64 20 61 70 70 6c 69 63 61 74 69 6f 6e } //1 not registred application
		$a_01_1 = {4d 61 67 69 63 53 4d 53 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //5 MagicSMSActivity.java
		$a_01_2 = {47 45 48 45 4e 20 53 50 } //5 GEHEN SP
		$a_01_3 = {41 43 43 45 53 53 20 53 50 } //5 ACCESS SP
		$a_01_4 = {57 55 55 54 } //1 WUUT
		$a_01_5 = {53 54 41 52 } //1 STAR
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}