
rule MonitoringTool_AndroidOS_FarMap_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/FarMap.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 4e 75 6d 5f 53 65 6e 64 74 6f } //1 PhoneNum_Sendto
		$a_01_1 = {66 75 6e 2e 66 4d 61 70 } //1 fun.fMap
		$a_01_2 = {73 50 68 6f 6e 65 4e 75 6d 5f 41 73 6b 66 6f 72 } //1 sPhoneNum_Askfor
		$a_01_3 = {2f 66 6d 61 70 2f 70 72 6f 63 2f 76 63 68 6b 2e 61 73 70 3f } //1 /fmap/proc/vchk.asp?
		$a_01_4 = {72 65 67 53 65 6e 64 53 4d 53 } //1 regSendSMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}