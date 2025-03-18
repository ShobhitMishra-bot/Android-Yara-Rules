
rule Trojan_AndroidOS_SmsThief_E{
	meta:
		description = "Trojan:AndroidOS/SmsThief.E,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 75 70 5f 66 69 6c 65 2e 70 68 70 3f 72 65 73 70 6f 6e 73 65 3d 74 72 75 65 26 69 64 3d } //2 /up_file.php?response=true&id=
		$a_01_1 = {26 61 63 74 69 6f 6e 3d 75 6e 73 65 6e 64 65 64 26 6d 6f 64 65 6c 3d } //2 &action=unsended&model=
		$a_01_2 = {50 72 69 76 61 74 65 2d 73 6d 73 2d 64 65 74 65 63 74 65 64 20 3a } //2 Private-sms-detected :
		$a_01_3 = {26 61 63 74 69 6f 6e 3d 73 6d 73 26 6e 65 74 77 6f 72 6b 3d } //2 &action=sms&network=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}