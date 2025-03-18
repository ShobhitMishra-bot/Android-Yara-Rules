
rule MonitoringTool_AndroidOS_Stealthcell_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Stealthcell.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 69 6e 66 6f 77 65 69 73 65 2e 70 61 72 65 6e 74 61 6c 63 6f 6e 74 72 6f 6c 2e 73 65 63 75 72 65 74 65 65 6e 2e 63 68 69 6c 64 } //1 com.infoweise.parentalcontrol.secureteen.child
		$a_00_1 = {45 6d 61 69 6c 47 50 53 53 65 72 76 69 63 65 } //1 EmailGPSService
		$a_00_2 = {43 61 6c 6c 50 61 72 72 65 6e 74 41 63 74 69 76 69 74 79 } //1 CallParrentActivity
		$a_00_3 = {73 65 63 75 72 65 74 65 65 6e 2e 63 6f 6d 2f 6c 6f 67 69 6e 2e 70 68 70 3f 75 73 65 72 5f 6e 61 6d 65 3d } //1 secureteen.com/login.php?user_name=
		$a_00_4 = {50 61 72 65 6e 74 53 65 6c 65 63 74 44 65 76 69 63 65 41 63 74 69 76 69 74 79 } //1 ParentSelectDeviceActivity
		$a_00_5 = {74 62 6c 5f 61 70 70 5f 75 73 61 67 65 5f 73 74 61 74 5f 6c 6f 6c 6c 69 70 6f 70 } //1 tbl_app_usage_stat_lollipop
		$a_00_6 = {2f 73 65 63 75 72 65 2f 75 70 64 61 74 65 2f 6c 6f 67 73 2f 73 75 6d 6d 61 72 79 3f 6d 61 70 70 69 6e 67 49 64 3d } //1 /secure/update/logs/summary?mappingId=
		$a_00_7 = {2f 73 65 63 75 72 65 2f 76 61 6c 69 64 61 74 65 2f 75 73 72 2f 70 77 64 2f 63 6f 64 65 } //1 /secure/validate/usr/pwd/code
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}