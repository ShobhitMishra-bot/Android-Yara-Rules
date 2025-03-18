
rule Trojan_AndroidOS_SmsSpy_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {4a 61 76 61 5f 63 6f 6d 5f 73 61 6d 73 75 6e 67 5f 61 70 70 73 74 6f 72 65 36 5f 4d 61 73 6b 65 72 5f 67 65 74 4d 73 67 } //2 Java_com_samsung_appstore6_Masker_getMsg
		$a_00_1 = {2f 61 70 69 5f 70 68 6f 6e 65 62 6f 6f 6b 2e 70 68 70 } //1 /api_phonebook.php
		$a_00_2 = {2f 61 70 69 5f 6d 73 67 2e 70 68 70 } //1 /api_msg.php
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}
rule Trojan_AndroidOS_SmsSpy_C_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 61 6d 73 75 6e 67 2f 61 70 70 73 74 6f 72 65 36 2f 50 47 5f 53 4d 53 4f 62 73 65 72 76 65 72 3b } //1 Lcom/samsung/appstore6/PG_SMSObserver;
		$a_00_1 = {43 46 5f 50 65 72 73 6f 6e 44 61 74 61 2e 6a 61 76 61 } //1 CF_PersonData.java
		$a_00_2 = {6d 61 32 73 6b 65 72 } //1 ma2sker
		$a_00_3 = {67 65 74 55 70 6c 6f 61 64 50 68 6f 6e 65 62 6f 6f 6b 58 4d 4c } //1 getUploadPhonebookXML
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}