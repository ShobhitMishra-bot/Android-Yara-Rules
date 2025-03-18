
rule Trojan_AndroidOS_Ahmythspy_A{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {78 30 30 30 30 66 6d } //2 x0000fm
		$a_01_1 = {72 62 6d 75 73 69 63 2f 53 4d 53 6d } //2 rbmusic/SMSm
		$a_01_2 = {2f 52 65 61 64 41 6c 6c 54 72 61 63 6b 73 2e 70 68 70 } //1 /ReadAllTracks.php
		$a_00_3 = {2f 73 64 66 73 35 32 37 34 2f 61 62 63 2e 70 68 70 3f 69 64 3d } //1 /sdfs5274/abc.php?id=
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}