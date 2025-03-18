
rule Trojan_AndroidOS_BoxerSms_B{
	meta:
		description = "Trojan:AndroidOS/BoxerSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 73 53 4d 53 4c 69 6d 69 74 45 6e 61 62 6c 65 64 } //1 isSMSLimitEnabled
		$a_01_1 = {6d 65 67 61 66 6f 6e 52 75 6c 65 73 } //1 megafonRules
		$a_01_2 = {67 65 74 52 75 6c 65 73 54 65 78 74 73 } //1 getRulesTexts
		$a_01_3 = {4f 70 49 6e 66 6f 2e 6a 61 76 61 } //1 OpInfo.java
		$a_01_4 = {61 75 74 68 53 75 63 63 65 73 73 } //1 authSuccess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}