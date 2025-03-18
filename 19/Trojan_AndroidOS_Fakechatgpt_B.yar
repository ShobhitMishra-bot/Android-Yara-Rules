
rule Trojan_AndroidOS_Fakechatgpt_B{
	meta:
		description = "Trojan:AndroidOS/Fakechatgpt.B,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6f 6e 65 73 69 67 6e 61 6c 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d 2f } //1 ://onesignal.modobomco.com/
		$a_01_1 = {2b 34 37 36 31 35 39 37 } //1 +4761597
		$a_01_2 = {68 75 79 63 6f 69 } //1 huycoi
		$a_01_3 = {53 45 4e 44 5f 41 49 53 } //1 SEND_AIS
		$a_01_4 = {43 68 61 74 47 50 54 } //1 ChatGPT
		$a_01_5 = {6d 63 63 5f 6d 6e 63 } //1 mcc_mnc
		$a_01_6 = {73 65 6e 73 6d 73 } //1 sensms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}