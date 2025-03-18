
rule TrojanSpy_AndroidOS_Keylogger_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Keylogger.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 67 2e 74 78 74 } //1 log.txt
		$a_00_1 = {4c 63 6f 6d 2f 6b 65 79 6c 6f 67 67 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 Lcom/keylogger/MainActivity
		$a_00_2 = {64 6f 69 6e 62 61 63 6b 67 72 6f 75 6e 64 } //1 doinbackground
		$a_00_3 = {66 69 78 2e 64 61 74 } //1 fix.dat
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}