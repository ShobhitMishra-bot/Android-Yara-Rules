
rule TrojanSpy_AndroidOS_Marcher_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Marcher.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 5f 73 6d 73 2e 70 68 70 } //1 load_sms.php
		$a_01_1 = {73 65 74 5f 63 61 72 64 2e 70 68 70 } //1 set_card.php
		$a_01_2 = {73 65 74 5f 63 6f 6d 6d 65 72 7a 62 61 6e 6b 2e 70 68 70 } //1 set_commerzbank.php
		$a_01_3 = {73 6d 73 5f 68 6f 6f 6b } //1 sms_hook
		$a_01_4 = {61 75 2e 63 6f 6d 2e 6e 61 62 2e 6d 6f 62 69 6c 65 } //1 au.com.nab.mobile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}