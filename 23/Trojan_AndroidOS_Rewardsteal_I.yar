
rule Trojan_AndroidOS_Rewardsteal_I{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.I,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 67 6c 65 70 72 6f 74 65 63 74 2f 54 68 69 72 64 41 63 74 69 76 69 74 79 } //2 googleprotect/ThirdActivity
		$a_01_1 = {2f 61 70 69 2f 75 73 65 72 2f 73 74 65 70 31 } //2 /api/user/step1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}