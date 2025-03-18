
rule Trojan_AndroidOS_PJobRat_A{
	meta:
		description = "Trojan:AndroidOS/PJobRat.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 70 5f 6b 65 79 5f 73 63 72 65 65 6e 5f 77 69 64 74 68 } //1 sp_key_screen_width
		$a_03_1 = {44 42 5f 52 45 46 5f 4f 4e 4c 49 4e 45 [0-01] 53 54 41 54 55 53 } //1
		$a_00_2 = {53 65 65 59 6f 75 2e 73 61 76 65 55 73 65 72 46 63 6d 2e 6f 6e 53 75 63 63 65 73 73 28 29 } //1 SeeYou.saveUserFcm.onSuccess()
		$a_00_3 = {73 65 65 5f 79 6f 75 5f 70 72 65 66 73 } //1 see_you_prefs
		$a_00_4 = {69 73 53 74 6f 72 61 67 65 50 72 65 6d 47 72 61 6e 74 65 64 } //1 isStoragePremGranted
		$a_01_5 = {43 41 53 45 5f 41 50 50 5f 44 42 } //1 CASE_APP_DB
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}