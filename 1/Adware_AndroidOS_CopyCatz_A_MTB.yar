
rule Adware_AndroidOS_CopyCatz_A_MTB{
	meta:
		description = "Adware:AndroidOS/CopyCatz.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 74 64 63 2e 61 64 73 65 72 76 69 63 65 } //10 com.tdc.adservice
		$a_01_1 = {63 6f 6d 2e 6e 65 6e 64 2e 61 64 73 65 72 76 69 63 65 } //10 com.nend.adservice
		$a_01_2 = {63 6f 6d 2e 65 6c 69 73 65 2e 61 64 73 65 72 76 69 63 65 } //10 com.elise.adservice
		$a_01_3 = {63 6f 6d 2e 56 70 6f 6e 2e 61 64 73 65 72 76 69 63 65 } //10 com.Vpon.adservice
		$a_01_4 = {63 6f 6d 2e 56 75 6e 67 6c 65 2e 61 64 73 65 72 76 69 63 65 } //10 com.Vungle.adservice
		$a_01_5 = {63 6f 6d 2e 75 6d 65 6e 67 2e 61 64 73 65 72 76 69 63 65 } //10 com.umeng.adservice
		$a_01_6 = {63 6f 6d 2e 6d 61 69 6f 2e 61 64 73 65 72 76 69 63 65 } //10 com.maio.adservice
		$a_01_7 = {66 75 6c 6c 41 64 49 64 } //1 fullAdId
		$a_01_8 = {72 65 71 75 65 73 74 4e 65 77 49 6e 74 65 72 73 74 69 74 69 61 6c } //1 requestNewInterstitial
		$a_01_9 = {41 64 73 4a 6f 62 } //1 AdsJob
		$a_01_10 = {61 64 73 41 63 74 69 76 69 74 79 } //1 adsActivity
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=14
 
}