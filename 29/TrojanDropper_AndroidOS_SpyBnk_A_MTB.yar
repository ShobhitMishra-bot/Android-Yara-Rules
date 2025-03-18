
rule TrojanDropper_AndroidOS_SpyBnk_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SpyBnk.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {07 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 10 ?? ?? 07 00 0c 03 22 04 ?? ?? 70 10 ?? ?? 04 00 22 05 ?? ?? 70 10 ?? ?? 05 00 6e 10 ?? ?? 02 00 0c 06 6e 20 ?? ?? 65 00 1a 06 03 00 6e 20 ?? ?? 65 00 6e 10 ?? ?? 05 00 0c 05 6e 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 54 00 6e 10 } //1
		$a_02_1 = {07 00 0c 05 6e 20 0d 00 25 00 0c 02 12 05 46 02 02 05 6e 20 ?? ?? 24 00 6e 10 ?? ?? 04 00 0c 02 6e 20 0e 00 23 00 0c 02 13 03 0b 00 23 33 34 00 6e 20 ?? ?? 32 00 13 04 08 00 48 05 03 04 d5 55 ff 00 e0 05 05 10 13 06 09 00 48 06 03 06 d5 66 ff 00 e0 04 06 08 b6 54 13 05 0a 00 48 03 03 05 d5 33 ff 00 b6 43 6e 10 ?? ?? 02 00 0a 04 70 54 } //1
		$a_00_2 = {67 65 74 41 73 73 65 74 73 } //1 getAssets
		$a_00_3 = {2f 4a 78 41 70 70 6c 69 63 61 74 69 6f 6e 3b } //1 /JxApplication;
		$a_00_4 = {2f 4b 39 52 65 63 65 69 76 65 72 3b } //1 /K9Receiver;
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}