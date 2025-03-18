
rule MonitoringTool_AndroidOS_Kidguard_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Kidguard.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 65 78 74 5f 6c 6f 63 61 74 69 6f 6e 5f 61 6e 64 5f 73 6d 73 5f 70 65 72 6d 69 73 73 69 6f 6e } //1 text_location_and_sms_permission
		$a_01_1 = {70 65 72 6d 69 73 73 69 6f 6e 5f 73 63 72 65 65 6e 5f 63 61 70 74 75 72 65 5f 6d 65 73 73 } //1 permission_screen_capture_mess
		$a_01_2 = {63 6f 6d 2f 6b 69 64 73 2f 70 72 6f } //1 com/kids/pro
		$a_01_3 = {4b 69 64 73 48 74 74 70 4c 6f 67 } //1 KidsHttpLog
		$a_01_4 = {74 69 70 5f 6e 6f 74 5f 70 65 72 6d 69 73 73 69 6f 6e 5f 64 72 61 77 5f 6f 76 65 72 6c 61 79 73 } //1 tip_not_permission_draw_overlays
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}