
rule Trojan_AndroidOS_PJobRat_B{
	meta:
		description = "Trojan:AndroidOS/PJobRat.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 70 5f 6b 65 79 5f 73 63 72 65 65 6e 5f 77 69 64 74 68 } //1 sp_key_screen_width
		$a_00_1 = {41 70 70 73 44 65 74 61 69 6c 52 65 63 65 69 76 65 72 } //1 AppsDetailReceiver
		$a_00_2 = {70 6f 77 65 72 53 61 76 65 64 4d 6f 64 65 52 65 63 65 69 76 65 72 } //1 powerSavedModeReceiver
		$a_00_3 = {6a 6f 62 73 2f 4a 6f 62 43 6f 6e 74 61 63 74 3b } //1 jobs/JobContact;
		$a_00_4 = {6f 62 73 65 72 76 65 72 2f 41 75 64 69 6f 4f 62 73 65 72 76 65 72 3b } //1 observer/AudioObserver;
		$a_00_5 = {50 52 4f 46 49 4c 45 5f 50 49 43 5f 53 54 4f 52 41 47 45 5f 52 45 46 5f 4e 41 4d 45 } //1 PROFILE_PIC_STORAGE_REF_NAME
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}