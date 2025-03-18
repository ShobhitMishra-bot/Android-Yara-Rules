
rule Trojan_AndroidOS_Hyspu_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hyspu.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 61 79 45 6e 74 72 79 } //1 PayEntry
		$a_00_1 = {73 6d 73 20 64 65 6c 65 74 65 20 63 74 72 6c } //1 sms delete ctrl
		$a_00_2 = {72 65 6d 5f 66 65 65 5f 62 65 67 69 6e } //1 rem_fee_begin
		$a_00_3 = {73 6d 73 5f 72 65 6d 5f 69 6e 74 65 72 76 61 6c } //1 sms_rem_interval
		$a_00_4 = {6e 65 77 70 61 79 73 64 6b } //1 newpaysdk
		$a_00_5 = {63 6e 66 53 6d 73 46 69 6c 74 65 72 20 6d 61 74 63 68 } //1 cnfSmsFilter match
		$a_00_6 = {53 6d 73 53 65 6e 64 43 61 6c 6c 62 61 63 6b 20 6f 6e 53 65 6e 64 53 75 63 63 65 73 73 } //1 SmsSendCallback onSendSuccess
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}