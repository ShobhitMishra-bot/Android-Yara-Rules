
rule Trojan_AndroidOS_SMSSend_C_xp{
	meta:
		description = "Trojan:AndroidOS/SMSSend.C!xp,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 53 65 6e 64 53 6d 73 20 74 68 72 65 61 64 20 73 74 61 72 74 } //1 deleteSendSms thread start
		$a_00_1 = {64 65 6c 65 74 65 53 6d 73 20 2d 3e 20 } //1 deleteSms -> 
		$a_00_2 = {73 65 6e 64 73 6d 73 } //1 sendsms
		$a_00_3 = {61 70 70 62 6f 78 2e 64 62 } //1 appbox.db
		$a_00_4 = {44 45 4c 49 56 45 52 45 44 5f 53 4d 53 5f 41 43 54 49 4f 4e } //1 DELIVERED_SMS_ACTION
		$a_00_5 = {53 45 4e 54 5f 53 4d 53 5f 41 43 54 49 4f 4e } //1 SENT_SMS_ACTION
		$a_00_6 = {73 65 6e 64 73 74 61 74 75 73 } //1 sendstatus
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}