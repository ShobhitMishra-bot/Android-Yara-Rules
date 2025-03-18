
rule Trojan_AndroidOS_SAgent_J_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 75 2f 6d 69 73 68 61 2f 73 6d 73 62 75 79 } //1 ru/misha/smsbuy
		$a_01_1 = {69 73 5f 6d 79 5f 6d 65 73 73 61 67 65 73 } //1 is_my_messages
		$a_01_2 = {54 55 4d 42 4c 45 52 5f 49 44 53 } //1 TUMBLER_IDS
		$a_01_3 = {53 4d 53 4f 62 73 65 72 76 65 72 5f 42 61 6c 61 6e 63 65 } //1 SMSObserver_Balance
		$a_01_4 = {56 61 6c 69 64 42 61 6c 61 6e 63 65 53 4d 53 } //1 ValidBalanceSMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}