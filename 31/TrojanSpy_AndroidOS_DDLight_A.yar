
rule TrojanSpy_AndroidOS_DDLight_A{
	meta:
		description = "TrojanSpy:AndroidOS/DDLight.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 65 64 50 72 6f 64 75 63 74 49 6e 66 6f } //1 InstalledProductInfo
		$a_01_1 = {2f 6c 69 67 68 74 64 64 2f 43 6f 72 65 53 65 72 76 69 63 65 } //1 /lightdd/CoreService
		$a_01_2 = {70 72 65 66 65 72 2e 64 61 74 } //1 prefer.dat
		$a_01_3 = {4d 6f 62 69 6c 65 49 6e 66 6f } //1 MobileInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}