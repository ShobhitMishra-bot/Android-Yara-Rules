
rule Backdoor_AndroidOS_Forav_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Forav.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 62 2f 63 73 6f 62 2f 70 6b 67 2f 41 41 63 74 } //1 ib/csob/pkg/AAct
		$a_01_1 = {6d 79 6c 6f 67 5f 63 6d 64 } //1 mylog_cmd
		$a_01_2 = {6d 79 6c 6f 67 5f 6d 65 73 73 } //1 mylog_mess
		$a_01_3 = {6d 79 6c 6f 67 5f 68 65 78 5f 78 6f 72 } //1 mylog_hex_xor
		$a_01_4 = {2f 42 4e 50 69 } //1 /BNPi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}