
rule TrojanSpy_AndroidOS_SmsThief_Y{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Y,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {61 70 69 5f 73 70 61 [0-20] 2f 61 70 69 5f 65 73 70 61 6e 6f 6c 2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //10
		$a_00_1 = {6f 6e 6c 69 6e 65 2f 61 70 70 5f 61 62 63 37 37 31 5f 32 73 66 61 63 73 6c 66 66 66 63 73 32 2f } //10 online/app_abc771_2sfacslfffcs2/
		$a_00_2 = {5f 38 38 38 61 2f 61 70 69 2f 61 70 69 2e 70 68 70 3f 67 65 74 5f 74 61 78 5f 63 75 72 72 65 6e 63 79 } //10 _888a/api/api.php?get_tax_currency
		$a_00_3 = {50 6c 65 61 73 65 20 61 6c 6c 6f 77 20 53 4d 53 20 62 65 66 6f 72 65 20 70 72 6f 63 65 65 64 20 6f 72 20 72 65 69 6e 73 74 61 6c 6c 20 74 68 65 20 61 70 70 } //1 Please allow SMS before proceed or reinstall the app
		$a_00_4 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=12
 
}