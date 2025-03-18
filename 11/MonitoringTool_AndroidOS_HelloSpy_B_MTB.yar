
rule MonitoringTool_AndroidOS_HelloSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/HelloSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 54 6f 41 70 70 } //1 SpyToApp
		$a_00_1 = {43 41 54 43 48 20 50 48 4f 54 4f 20 4c 4f 47 } //1 CATCH PHOTO LOG
		$a_00_2 = {46 4f 52 43 45 20 53 54 41 52 54 20 43 4f 52 45 53 50 59 53 45 52 56 49 43 45 } //1 FORCE START CORESPYSERVICE
		$a_00_3 = {53 65 6e 64 44 61 74 61 4d 61 6e 61 67 65 72 46 6f 72 57 68 61 74 73 61 70 70 } //1 SendDataManagerForWhatsapp
		$a_00_4 = {2f 73 79 6e 63 64 61 74 61 2f 55 70 64 61 74 65 50 68 6f 6e 65 49 6e 66 6f 2f } //1 /syncdata/UpdatePhoneInfo/
		$a_00_5 = {43 6f 6e 74 65 6e 74 4f 62 73 65 72 76 65 72 46 6f 72 53 6d 73 } //1 ContentObserverForSms
		$a_00_6 = {6f 62 73 65 72 76 65 72 41 70 70 4c 6f 67 } //1 observerAppLog
		$a_00_7 = {53 4d 53 5f 4f 55 54 47 4f 49 4e 47 5f 4c 4f 47 } //1 SMS_OUTGOING_LOG
		$a_00_8 = {52 65 63 6f 72 64 43 61 6c 6c 53 65 72 76 69 63 65 } //1 RecordCallService
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}