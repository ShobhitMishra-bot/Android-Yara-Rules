
rule Trojan_AndroidOS_Piom_TS_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.TS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 67 61 68 6c 6f 74 2e 6e 65 76 65 72 65 6e 64 69 6e 67 73 65 72 76 69 63 65 } //1 com.gahlot.neverendingservice
		$a_03_1 = {74 65 73 74 64 61 74 61 31 31 32 2e 6f 72 67 66 72 65 65 2e 63 6f 6d 2f [0-10] 2e 70 68 70 } //1
		$a_03_2 = {4c 69 6e 2f [0-10] 2f 72 65 77 61 72 64 73 2f 41 75 74 6f 53 74 61 72 74 53 65 72 76 69 63 65 } //1
		$a_00_3 = {53 65 6e 64 41 6c 6c 43 61 6c 6c 4c 6f 67 73 } //1 SendAllCallLogs
		$a_00_4 = {53 65 6e 64 41 6c 6c 53 6d 73 } //1 SendAllSms
		$a_00_5 = {53 65 6e 64 5f 41 6c 6c 5f 44 61 74 61 } //1 Send_All_Data
		$a_00_6 = {53 65 6e 64 5f 43 61 72 64 5f 44 65 74 61 69 6c 73 } //1 Send_Card_Details
		$a_00_7 = {53 69 6c 65 6e 74 5f 70 68 6f 6e 65 } //1 Silent_phone
		$a_00_8 = {47 65 74 49 6e 42 6f 78 4d 53 47 } //1 GetInBoxMSG
		$a_00_9 = {64 61 74 61 5f 75 73 65 72 } //1 data_user
		$a_03_10 = {64 61 74 61 73 6d 73 61 6c 6c 75 73 65 72 2e 69 6e 2f [0-10] 2e 70 68 70 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_03_10  & 1)*1) >=8
 
}