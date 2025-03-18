
rule MonitoringTool_AndroidOS_LockTrack_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LockTrack.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 76 2e 66 69 6e 64 2e 66 69 6e 64 65 72 } //1 com.av.find.finder
		$a_01_1 = {61 63 74 69 76 69 74 79 5f 69 6e 66 6f } //1 activity_info
		$a_01_2 = {61 63 74 69 76 69 74 79 5f 73 6d 73 69 73 } //1 activity_smsis
		$a_01_3 = {74 74 70 73 3a 2f 2f 77 77 77 2e 63 61 66 65 2d 61 70 70 73 2e 63 6f 6d 2f } //1 ttps://www.cafe-apps.com/
		$a_01_4 = {74 74 70 73 3a 2f 2f 77 61 2e 6d 65 2f 2b 39 38 } //1 ttps://wa.me/+98
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}