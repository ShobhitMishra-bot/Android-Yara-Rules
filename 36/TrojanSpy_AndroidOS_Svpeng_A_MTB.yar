
rule TrojanSpy_AndroidOS_Svpeng_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 76 42 71 69 78 2f 66 42 71 4f 75 68 2f 70 71 79 64 51 73 6a 79 6c 79 6a 4f } //1 seC/vBqix/fBqOuh/pqydQsjylyjO
		$a_01_1 = {4e 6f 4e 65 4e 6f 4e 65 } //1 NoNeNoNe
		$a_01_2 = {73 6d 73 67 72 61 62 } //1 smsgrab
		$a_01_3 = {73 74 61 72 74 5f 73 6d 73 5f 67 72 61 62 } //1 start_sms_grab
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanSpy_AndroidOS_Svpeng_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 5f 68 69 73 74 6f 72 79 } //1 sms_history
		$a_00_1 = {63 61 6c 6c 5f 6c 6f 67 } //1 call_log
		$a_00_2 = {62 72 6f 77 73 65 72 5f 68 69 73 74 6f 72 79 } //1 browser_history
		$a_00_3 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //1 card_number
		$a_00_4 = {73 61 76 65 5f 63 61 72 64 } //1 save_card
		$a_01_5 = {46 49 4c 45 5f 43 41 4c 4c 53 } //1 FILE_CALLS
		$a_01_6 = {57 41 52 4e 49 4e 47 21 20 59 6f 75 72 20 64 65 76 69 63 65 20 77 69 6c 6c 20 6e 6f 77 20 72 65 62 6f 6f 74 20 74 6f 20 66 61 63 74 6f 72 79 20 73 65 74 74 69 6e 67 73 2e } //1 WARNING! Your device will now reboot to factory settings.
		$a_03_7 = {43 6c 69 63 6b [0-10] 74 6f 20 65 72 61 73 65 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 63 6f 6e 74 69 6e 75 65 [0-08] 66 6f 72 20 63 61 6e 63 65 6c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}