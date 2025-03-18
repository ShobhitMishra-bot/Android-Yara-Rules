
rule TrojanSpy_AndroidOS_Grvity_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Grvity.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {74 74 70 3a 2f 2f 6e [0-03] 2e 6e 6f 72 74 6f 6e 75 70 64 61 74 65 73 2e 6f 6e 6c 69 6e 65 } //3
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 2e 73 61 76 69 74 61 62 68 61 62 69 } //1 download.savitabhabi
		$a_00_2 = {47 65 74 41 63 74 69 76 65 50 72 69 76 61 74 65 44 6f 6d 61 69 6e } //1 GetActivePrivateDomain
		$a_00_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 70 69 6e 67 20 2d 63 20 31 } //1 /system/bin/ping -c 1
		$a_00_4 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } //1 getCallsLogs
		$a_00_5 = {67 65 74 53 4d 53 4c 69 73 74 } //1 getSMSList
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}