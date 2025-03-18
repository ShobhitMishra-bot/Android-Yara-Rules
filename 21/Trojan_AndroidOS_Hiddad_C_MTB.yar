
rule Trojan_AndroidOS_Hiddad_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 41 64 4c 6f 61 64 65 64 } //1 onAdLoaded
		$a_00_1 = {73 64 6b 2f 49 6e 6a 65 63 74 6f 72 } //1 sdk/Injector
		$a_00_2 = {61 63 61 6c 61 6d 61 6e 2e 63 6f 6d } //1 acalaman.com
		$a_00_3 = {73 65 74 41 64 4c 69 73 74 65 6e 65 72 } //1 setAdListener
		$a_00_4 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //1 setComponentEnabledSetting
		$a_00_5 = {63 6f 6d 2f 61 64 63 6f 6d 6d 65 72 63 69 61 6c 2f 75 74 69 6c 73 2f 54 72 69 70 6c 65 } //1 com/adcommercial/utils/Triple
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}