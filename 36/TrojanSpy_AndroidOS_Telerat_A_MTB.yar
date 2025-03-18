
rule TrojanSpy_AndroidOS_Telerat_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Telerat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 61 6c 6c 73 6d 73 5f 72 65 61 6c 72 61 74 } //1 getallsms_realrat
		$a_00_1 = {69 6e 73 74 61 6c 6c 5f 72 65 61 6c 72 61 74 } //1 install_realrat
		$a_00_2 = {72 65 61 6c 72 61 74 2e 66 75 63 6b 2e 63 6d 64 5f 72 65 61 6c 72 61 74 } //1 realrat.fuck.cmd_realrat
		$a_00_3 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SMSInterceptor
		$a_00_4 = {50 68 6f 6e 65 53 6d 73 } //1 PhoneSms
		$a_00_5 = {68 69 64 65 5f 72 65 61 6c 72 61 74 } //1 hide_realrat
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}