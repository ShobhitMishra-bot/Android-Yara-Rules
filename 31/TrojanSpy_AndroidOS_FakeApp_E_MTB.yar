
rule TrojanSpy_AndroidOS_FakeApp_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 50 68 6f 74 6f 4c 69 73 74 } //1 systemPhotoList
		$a_01_1 = {2e 66 69 74 2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f } //1 .fit/api/uploads/
		$a_01_2 = {77 78 61 63 37 31 66 61 34 33 61 39 37 37 37 36 63 31 } //1 wxac71fa43a97776c1
		$a_01_3 = {6f 6e 4c 6f 63 61 74 69 6f 6e 43 68 61 6e 67 65 64 73 } //1 onLocationChangeds
		$a_01_4 = {6b 69 6c 6c 41 6c 6c } //1 killAll
		$a_01_5 = {69 73 44 65 62 75 67 67 65 72 43 6f 6e 6e 65 63 74 65 64 } //1 isDebuggerConnected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}