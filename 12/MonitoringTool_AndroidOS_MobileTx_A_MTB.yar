
rule MonitoringTool_AndroidOS_MobileTx_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTx.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 49 44 45 5f 41 44 } //1 HIDE_AD
		$a_01_1 = {54 78 41 63 74 69 76 69 74 79 } //1 TxActivity
		$a_01_2 = {64 6f 53 68 6f 65 77 41 64 } //1 doShoewAd
		$a_01_3 = {4c 6f 61 64 41 64 54 61 73 6b } //1 LoadAdTask
		$a_01_4 = {63 72 61 65 74 54 68 72 65 61 64 4c 6f 61 64 41 44 } //1 craetThreadLoadAD
		$a_03_5 = {4c 63 6f 6d 2f 74 78 2f [0-10] 2f 56 61 6c 69 64 61 74 65 41 73 79 6e 63 54 61 73 6b } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*5) >=9
 
}