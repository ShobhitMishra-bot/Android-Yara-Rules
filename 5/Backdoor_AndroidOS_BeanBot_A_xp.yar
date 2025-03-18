
rule Backdoor_AndroidOS_BeanBot_A_xp{
	meta:
		description = "Backdoor:AndroidOS/BeanBot.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 69 50 68 61 6e 64 2e 46 69 72 73 74 41 69 64 2f 64 61 74 61 62 61 73 65 73 } //1 data/data/com.iPhand.FirstAid/databases
		$a_00_1 = {63 6f 6d 2e 61 6e 64 2e 73 6d 73 2e 73 65 6e 64 } //1 com.and.sms.send
		$a_00_2 = {63 6f 6d 2e 61 6e 64 2e 73 6d 73 2e 64 65 6c 69 76 65 72 79 } //1 com.and.sms.delivery
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}