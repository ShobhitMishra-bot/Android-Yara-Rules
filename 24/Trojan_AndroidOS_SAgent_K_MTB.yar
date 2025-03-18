
rule Trojan_AndroidOS_SAgent_K_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 65 74 65 46 6f 64 65 72 31 } //1 deleteFoder1
		$a_01_1 = {75 70 64 53 65 6e 64 53 4d 53 53 74 61 74 75 73 } //1 updSendSMSStatus
		$a_01_2 = {62 61 6e 6b 48 69 6a 61 63 6b } //1 bankHijack
		$a_01_3 = {42 41 4e 4b 5f 54 4f 50 5f 43 48 45 43 4b 5f 54 49 4d 45 } //1 BANK_TOP_CHECK_TIME
		$a_01_4 = {73 65 6e 64 53 4d 53 53 65 72 76 69 63 65 } //1 sendSMSService
		$a_01_5 = {75 70 6c 6f 61 64 50 68 6f 6e 65 } //1 uploadPhone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}