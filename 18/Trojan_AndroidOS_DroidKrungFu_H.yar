
rule Trojan_AndroidOS_DroidKrungFu_H{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 6c 61 6e 3d 7a 68 26 63 6f 75 6e 74 72 79 3d 43 4e 26 6e 65 74 77 6f 72 6b 3d } //1 &lan=zh&country=CN&network=
		$a_03_1 = {26 70 61 64 3d 30 26 6d 61 3d 32 2e 33 2e ?? 2c 41 6e 64 72 6f 69 64 25 32 30 } //1
		$a_01_2 = {61 64 2e 67 6f 6e 67 66 75 2d 61 6e 64 72 6f 69 64 2e 63 6f 6d 3a 37 35 30 30 2f 61 64 } //2 ad.gongfu-android.com:7500/ad
		$a_01_3 = {64 64 2e 70 68 6f 6e 65 67 6f 38 2e 63 6f 6d 3a 37 35 30 30 2f 61 64 } //2 dd.phonego8.com:7500/ad
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}