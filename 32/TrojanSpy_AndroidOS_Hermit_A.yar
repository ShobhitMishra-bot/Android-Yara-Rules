
rule TrojanSpy_AndroidOS_Hermit_A{
	meta:
		description = "TrojanSpy:AndroidOS/Hermit.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {52 4f 4f 54 5f 49 4e 46 4f 5f 53 55 43 43 45 44 45 44 } //1 ROOT_INFO_SUCCEDED
		$a_00_1 = {52 55 4e 4e 49 4e 47 5f 41 50 50 5f 50 52 4f 43 45 53 53 } //1 RUNNING_APP_PROCESS
		$a_00_2 = {76 70 73 73 65 65 64 } //1 vpsseed
		$a_00_3 = {4c 4f 43 41 54 49 4f 4e 5f 49 4e 46 4f 5f 43 48 41 4e 47 45 44 } //1 LOCATION_INFO_CHANGED
		$a_00_4 = {50 4c 41 54 46 4f 52 4d 5f 4c 45 56 45 4c 53 5f 43 48 41 4e 47 45 53 } //1 PLATFORM_LEVELS_CHANGES
		$a_00_5 = {73 65 74 43 65 6c 6c 75 6c 61 72 55 70 6c 6f 61 64 } //1 setCellularUpload
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}