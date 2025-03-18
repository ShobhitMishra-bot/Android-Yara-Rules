
rule Trojan_AndroidOS_FakeApp_H_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {66 6c 69 78 6f 6e 6c 69 6e 65 [0-01] 2f 63 68 65 63 6b 53 65 72 76 65 72 41 6e 64 45 78 65 63 75 74 65 3b } //1
		$a_02_1 = {66 6c 69 78 6f 6e 6c 69 6e 65 [0-01] 2f 54 68 65 4a 6f 62 43 68 72 6f 6d 69 75 6d 3b } //1
		$a_00_2 = {67 65 74 20 64 61 74 61 20 66 72 6f 6d 20 73 65 72 76 65 72 } //1 get data from server
		$a_00_3 = {62 72 6f 77 73 65 72 5f 75 72 6c } //1 browser_url
		$a_00_4 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 63 68 72 6f 6d 65 2f 63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 63 68 72 6f 6d 65 2e 4d 61 69 6e } //1 com.android.chrome/com.android.chrome.Main
		$a_00_5 = {63 6f 6d 2e 77 68 61 74 73 61 70 70 } //1 com.whatsapp
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}