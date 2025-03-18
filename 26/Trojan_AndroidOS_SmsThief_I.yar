
rule Trojan_AndroidOS_SmsThief_I{
	meta:
		description = "Trojan:AndroidOS/SmsThief.I,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 } //2 hp_getsmsblockstate.php
		$a_01_1 = {73 6d 73 5f 62 6c 6f 63 6b 73 74 61 74 65 } //2 sms_blockstate
		$a_01_2 = {77 68 61 74 5f 74 65 6c 5f 63 6f 6d } //2 what_tel_com
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}