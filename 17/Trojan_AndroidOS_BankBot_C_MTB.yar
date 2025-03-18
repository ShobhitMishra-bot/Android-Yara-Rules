
rule Trojan_AndroidOS_BankBot_C_MTB{
	meta:
		description = "Trojan:AndroidOS/BankBot.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {65 6e 68 61 6e 63 65 72 65 63 79 63 6c 65 2e 6a 61 76 61 } //1 enhancerecycle.java
		$a_00_1 = {6a 61 76 61 78 2f 69 6e 6a 65 63 74 2f 50 72 6f 76 69 64 65 72 3b } //1 javax/inject/Provider;
		$a_00_2 = {61 72 72 61 6e 67 65 61 74 74 61 63 6b } //1 arrangeattack
		$a_00_3 = {73 65 74 4d 61 63 72 6f 4f 6e 41 63 74 69 6f 6e } //1 setMacroOnAction
		$a_00_4 = {74 68 72 6f 77 4f 6e 53 65 74 53 63 72 65 65 6e 73 68 6f 74 42 75 74 4e 6f 50 69 69 41 6c 6c 6f 77 65 64 } //1 throwOnSetScreenshotButNoPiiAllowed
		$a_00_5 = {74 6f 72 74 6f 69 73 65 65 76 69 6c } //1 tortoiseevil
		$a_00_6 = {50 65 72 73 69 73 74 65 6e 74 20 43 6f 6f 6b 69 65 20 77 61 73 20 65 78 70 65 63 74 65 64 } //1 Persistent Cookie was expected
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}