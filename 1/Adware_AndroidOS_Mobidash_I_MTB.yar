
rule Adware_AndroidOS_Mobidash_I_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 70 65 6c 6c 69 6e 67 62 75 67 68 61 6e 67 6d 61 6e 6c 69 74 65 2e 64 62 } //2 spellingbughangmanlite.db
		$a_01_1 = {6d 61 78 68 65 61 6c 74 68 63 61 72 65 2e 64 62 } //2 maxhealthcare.db
		$a_01_2 = {63 6f 6d 2f 72 65 61 6c 74 65 73 74 2f 6e 61 6d 65 6d 65 74 65 72 2f 6c 6f 76 65 63 61 6c 63 75 6c 61 74 6f 72 2f 61 63 74 69 76 69 74 69 65 73 } //1 com/realtest/namemeter/lovecalculator/activities
		$a_01_3 = {72 6b 61 64 68 69 73 68 2f 61 6c 74 65 72 } //1 rkadhish/alter
		$a_01_4 = {64 72 61 6d 61 69 6e 66 6f 74 65 63 68 2e 63 6f 6d 2f 61 70 69 2f 6d 69 6c 65 73 74 6f 6e 65 2f 77 6f 72 64 2e 70 68 70 } //1 dramainfotech.com/api/milestone/word.php
		$a_01_5 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_6 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Adware_AndroidOS_Mobidash_I_MTB_2{
	meta:
		description = "Adware:AndroidOS/Mobidash.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 69 61 2f 72 6d 73 } //1 com/sia/rms
		$a_01_1 = {63 6f 6d 2f 4b 61 79 61 6c 2f 53 77 69 70 79 47 6f 61 6c } //1 com/Kayal/SwipyGoal
		$a_01_2 = {6f 72 67 2f 63 6f 63 6f 73 32 64 78 2f 63 70 70 } //1 org/cocos2dx/cpp
		$a_01_3 = {2f 73 62 43 39 71 37 } //1 /sbC9q7
		$a_03_4 = {13 00 00 10 23 01 ?? ?? 12 02 6e 40 ?? ?? 15 02 0a 03 3d 03 06 00 6e 40 ?? ?? 16 32 28 f6 0e 00 } //10
		$a_03_5 = {5e 00 00 00 54 40 ?? ?? 39 00 5b 00 71 10 ?? ?? 05 00 1a 00 ?? ?? 6e 20 ?? ?? 05 00 0c 01 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 05 00 0c 05 6e 10 ?? ?? 01 00 0c 03 38 03 13 00 6e 10 ?? ?? 01 00 0c 03 6e 10 ?? ?? 03 00 0a 03 39 03 09 00 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 01 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=21
 
}