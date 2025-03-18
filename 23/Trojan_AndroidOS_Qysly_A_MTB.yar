
rule Trojan_AndroidOS_Qysly_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Qysly.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {7a 71 70 6b 5f 64 6c 5f 69 73 73 65 6e 64 5f 6e 65 77 75 73 65 72 5f } //2 zqpk_dl_issend_newuser_
		$a_00_1 = {52 65 6d 6f 74 65 54 6f 6f 6c 73 2e 6a 61 72 } //1 RemoteTools.jar
		$a_00_2 = {63 6f 6d 2e 7a 68 69 71 75 70 6b 2e 72 6f 6f 74 } //1 com.zhiqupk.root
		$a_00_3 = {73 53 54 36 50 72 31 7a 4e 72 5a 6d 6d 46 37 34 } //1 sST6Pr1zNrZmmF74
		$a_00_4 = {73 79 6c 6c 79 71 31 6e 2e 63 6f 6d } //1 syllyq1n.com
		$a_00_5 = {77 6b 73 6e 6b 79 73 37 2e 63 6f 6d } //1 wksnkys7.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}