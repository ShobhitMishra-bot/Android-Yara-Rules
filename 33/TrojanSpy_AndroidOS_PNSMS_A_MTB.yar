
rule TrojanSpy_AndroidOS_PNSMS_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/PNSMS.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 64 61 74 61 2f 4d 65 73 73 61 67 65 2e 6f 6c 69 76 65 72 } //1 /data/Message.oliver
		$a_00_1 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 53 65 6e 64 69 6e 67 5f 73 6d 73 } //1 ResumableSub_Sending_sms
		$a_00_2 = {2f 64 61 74 61 2f 4e 75 6d 62 65 72 73 2e 6f 6c 69 76 65 72 } //1 /data/Numbers.oliver
		$a_02_3 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 73 6d 73 [0-04] 3d 67 65 74 } //1
		$a_00_4 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 75 70 6c 6f 61 64 73 6d 73 3d } //1 /panel.php?uploadsms=
		$a_00_5 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 75 70 6c 6f 61 64 63 6f 6e 3d } //1 /panel.php?uploadcon=
		$a_00_6 = {6f 6c 69 76 65 72 68 6f 6d 65 2e 6d 6c } //1 oliverhome.ml
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}