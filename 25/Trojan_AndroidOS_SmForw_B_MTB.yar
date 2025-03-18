
rule Trojan_AndroidOS_SmForw_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SmForw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 72 67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 49 6e 70 75 74 } //1 targetPhoneNumberInput
		$a_01_1 = {6b 69 6c 6c 5f 61 70 70 5f 68 69 6e 74 5f 74 65 78 74 } //1 kill_app_hint_text
		$a_01_2 = {64 65 66 61 75 6c 74 5f 66 6f 72 77 61 72 64 5f 6e 75 6d 62 65 72 } //1 default_forward_number
		$a_01_3 = {74 61 72 67 65 74 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 5f 6b 65 79 } //1 target_phone_number_key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}