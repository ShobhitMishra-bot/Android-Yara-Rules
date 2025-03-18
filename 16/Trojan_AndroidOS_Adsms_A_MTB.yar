
rule Trojan_AndroidOS_Adsms_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Adsms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {45 76 61 6e 2e 42 61 63 6b 67 72 6f 75 6e 64 53 4d 53 } //1 Evan.BackgroundSMS
		$a_01_1 = {49 4d 49 43 48 41 54 5f 53 45 52 56 49 43 45 } //1 IMICHAT_SERVICE
		$a_00_2 = {61 64 73 6d 73 2e 69 74 6f 64 6f 2e 63 6e 2f 53 75 62 6d 69 74 } //1 adsms.itodo.cn/Submit
		$a_00_3 = {49 73 46 75 63 6b 53 65 6e 64 } //1 IsFuckSend
		$a_00_4 = {6b 69 6c 6c 69 6e 73 74 61 6c 6c } //1 killinstall
		$a_00_5 = {71 71 74 6c 69 76 65 2e 61 70 6b } //1 qqtlive.apk
		$a_00_6 = {53 6d 73 43 6f 6e 66 69 67 55 52 4c } //1 SmsConfigURL
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}