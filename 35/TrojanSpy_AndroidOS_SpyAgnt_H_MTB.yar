
rule TrojanSpy_AndroidOS_SpyAgnt_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 61 79 6c 6f 61 64 73 2f 6e 65 77 53 68 65 6c 6c 3b } //1 Payloads/newShell;
		$a_00_1 = {50 61 79 6c 6f 61 64 73 2f 72 65 61 64 43 61 6c 6c 4c 6f 67 73 3b } //1 Payloads/readCallLogs;
		$a_00_2 = {73 74 61 72 74 46 6f 72 65 } //1 startFore
		$a_00_3 = {74 61 6b 65 73 63 72 65 65 6e 73 68 6f 74 } //1 takescreenshot
		$a_00_4 = {67 65 74 43 6c 69 70 44 61 74 61 } //1 getClipData
		$a_00_5 = {72 65 61 64 53 4d 53 42 6f 78 } //1 readSMSBox
		$a_00_6 = {73 65 6e 64 44 61 74 61 } //1 sendData
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}