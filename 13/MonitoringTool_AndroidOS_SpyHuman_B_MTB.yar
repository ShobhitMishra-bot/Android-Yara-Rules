
rule MonitoringTool_AndroidOS_SpyHuman_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHuman.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 48 75 6d 61 6e 55 70 6c 6f 61 64 } //1 SpyHumanUpload
		$a_00_1 = {53 70 79 48 75 6d 61 6e 4c 6f 63 61 74 69 6f 6e } //1 SpyHumanLocation
		$a_00_2 = {73 70 79 68 75 6d 61 6e 2e 63 6f 6d } //1 spyhuman.com
		$a_00_3 = {2f 2e 74 6d 70 79 73 6b } //1 /.tmpysk
		$a_00_4 = {50 68 6e 65 4c 69 73 74 65 6e 65 72 } //1 PhneListener
		$a_00_5 = {73 65 6e 64 64 61 74 61 } //1 senddata
		$a_00_6 = {73 6d 73 61 6c 6c 2e 70 68 70 } //1 smsall.php
		$a_00_7 = {73 74 6f 72 65 70 68 6f 6e 69 6e 66 6f 2e 70 68 70 } //1 storephoninfo.php
		$a_00_8 = {63 61 6c 6c 6c 6f 67 73 2e 70 68 70 } //1 calllogs.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}