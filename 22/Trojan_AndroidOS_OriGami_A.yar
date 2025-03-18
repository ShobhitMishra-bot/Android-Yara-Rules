
rule Trojan_AndroidOS_OriGami_A{
	meta:
		description = "Trojan:AndroidOS/OriGami.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 75 69 6f 66 63 76 64 51 32 46 73 62 41 3d 3d } //1 HuiofcvdQ2FsbA==
		$a_01_1 = {4c 49 4b 4b 20 53 61 76 65 20 45 72 72 6f 72 } //1 LIKK Save Error
		$a_01_2 = {74 6f 20 67 65 74 20 74 68 69 73 20 77 6f 72 6b 69 6e 67 2e 20 54 61 70 20 6f 6e 20 27 4f 6b 27 20 74 6f 20 67 6f 20 74 6f 20 41 63 63 65 73 73 69 62 69 6c 69 74 79 20 53 65 74 74 69 6e 67 73 } //1 to get this working. Tap on 'Ok' to go to Accessibility Settings
		$a_01_3 = {41 64 64 65 64 20 69 6e 20 63 61 6c 6c 20 6c 69 73 74 } //1 Added in call list
		$a_01_4 = {45 69 67 68 74 20 65 72 72 6f 72 20 69 6e 20 6e 65 20 73 74 6f 70 } //1 Eight error in ne stop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}