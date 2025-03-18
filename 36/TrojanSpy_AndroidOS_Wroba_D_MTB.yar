
rule TrojanSpy_AndroidOS_Wroba_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 43 72 65 64 69 74 43 61 72 64 54 79 70 65 43 68 61 6e 67 65 64 } //1 onCreditCardTypeChanged
		$a_00_1 = {2f 75 73 65 72 5f 69 6e 66 6f 5f 75 70 6c 6f 61 64 65 72 } //1 /user_info_uploader
		$a_00_2 = {2f 2e 75 70 64 61 74 65 32 2f } //1 /.update2/
		$a_00_3 = {73 6d 73 5f 6b 77 5f 73 65 6e 74 } //1 sms_kw_sent
		$a_00_4 = {69 73 5f 63 61 6c 6c 5f 72 65 63 5f 65 6e 61 62 6c 65 } //1 is_call_rec_enable
		$a_00_5 = {67 65 74 5f 67 61 6c 6c 65 72 79 } //1 get_gallery
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}