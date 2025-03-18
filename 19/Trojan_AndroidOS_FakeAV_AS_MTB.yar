
rule Trojan_AndroidOS_FakeAV_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeAV.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {4c 72 6f 69 6a 66 [0-20] 46 61 6b 65 41 63 74 69 76 69 74 79 } //1
		$a_00_1 = {2f 61 6e 62 75 69 6c 64 2e 64 65 78 } //1 /anbuild.dex
		$a_00_2 = {43 6c 65 61 6e 69 6e 67 20 75 70 3a } //1 Cleaning up:
		$a_00_3 = {6f 75 74 20 73 6d 73 3a } //1 out sms:
		$a_00_4 = {62 6c 6f 63 6b 50 68 6f 6e 65 73 } //1 blockPhones
		$a_00_5 = {4c 61 6e 74 69 76 69 72 75 73 2f 70 72 6f 2f } //1 Lantivirus/pro/
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}