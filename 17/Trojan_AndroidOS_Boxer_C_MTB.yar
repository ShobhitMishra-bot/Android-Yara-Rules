
rule Trojan_AndroidOS_Boxer_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 68 61 7a 75 75 2f 64 6f 6e 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b } //1 Lcom/hazuu/don/MainActivity;
		$a_01_1 = {43 41 4c 4c 42 41 43 4b 5f 55 52 4c } //1 CALLBACK_URL
		$a_01_2 = {73 65 6e 64 53 4d 53 } //1 sendSMS
		$a_01_3 = {61 31 34 66 39 38 63 30 62 64 66 31 36 30 36 } //1 a14f98c0bdf1606
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}