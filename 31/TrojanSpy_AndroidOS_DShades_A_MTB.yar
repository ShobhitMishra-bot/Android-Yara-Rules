
rule TrojanSpy_AndroidOS_DShades_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DShades.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {44 61 72 6b 5f 53 68 61 64 65 73 5f 45 6e 63 72 79 70 74 65 64 } //2 Dark_Shades_Encrypted
		$a_00_1 = {64 73 5f 75 63 6d 64 2e 70 68 70 3f 69 6d 65 69 3d } //1 ds_ucmd.php?imei=
		$a_00_2 = {70 6f 73 74 5f 67 70 73 2e 70 68 70 } //1 post_gps.php
		$a_00_3 = {44 41 52 4b 52 4f 47 55 45 } //1 DARKROGUE
		$a_00_4 = {64 73 5f 65 6d 61 69 6c 73 2e 70 68 70 } //1 ds_emails.php
		$a_00_5 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 /system/bin/screencap -p
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}