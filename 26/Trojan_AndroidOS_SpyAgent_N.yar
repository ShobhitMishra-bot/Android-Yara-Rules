
rule Trojan_AndroidOS_SpyAgent_N{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.N,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 68 6f 73 74 73 2f 64 65 76 69 63 65 2f 63 5f 73 5f 6d 3b } //2 /hosts/device/c_s_m;
		$a_01_1 = {63 6f 6d 2f 61 70 69 2f 67 65 74 6c 6f 67 69 6e 74 6f 6b 65 6e } //2 com/api/getlogintoken
		$a_01_2 = {53 4d 53 5f 41 5f 55 } //2 SMS_A_U
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}