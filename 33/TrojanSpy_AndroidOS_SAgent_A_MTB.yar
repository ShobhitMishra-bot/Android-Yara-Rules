
rule TrojanSpy_AndroidOS_SAgent_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {65 76 65 72 79 6f 6e 65 2e 65 76 6c } //1 everyone.evl
		$a_00_1 = {72 75 6e 20 54 6f 20 55 70 6c 6f 61 64 20 46 69 6c 65 73 20 52 65 63 65 69 76 65 72 } //1 run To Upload Files Receiver
		$a_01_2 = {52 49 4e 47 49 4e 47 20 49 6e 63 6f 6d 69 6e 67 20 43 61 6c 6c 52 65 63 65 69 76 65 64 20 2d 20 6c 61 73 74 20 73 74 61 74 75 73 3a } //1 RINGING Incoming CallReceived - last status:
		$a_00_3 = {53 63 68 52 65 63 6f 72 64 65 72 73 53 65 72 76 69 63 65 } //1 SchRecordersService
		$a_01_4 = {49 43 4f 4e 5f 48 49 44 44 45 4e } //1 ICON_HIDDEN
		$a_01_5 = {49 43 4f 4e 5f 43 48 41 4e 47 45 44 } //1 ICON_CHANGED
		$a_01_6 = {4f 50 45 4e 5f 41 55 54 4f 5f 53 54 41 52 54 } //1 OPEN_AUTO_START
		$a_00_7 = {53 4d 53 53 65 72 76 69 63 65 } //1 SMSService
		$a_00_8 = {43 61 6c 6c 4c 6f 67 53 65 72 76 69 63 65 } //1 CallLogService
		$a_00_9 = {55 70 6c 6f 61 64 46 69 6c 65 53 65 72 76 69 63 65 } //1 UploadFileService
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}