
rule Trojan_AndroidOS_Boogr_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 75 20 2d 63 20 63 61 74 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 77 68 61 74 73 61 70 70 2f 64 61 74 61 62 61 73 65 73 2f 6d 73 67 73 74 6f 72 65 2e 64 62 } //1 su -c cat /data/data/com.whatsapp/databases/msgstore.db
		$a_00_1 = {63 79 62 65 72 63 6f 70 72 61 68 75 6c 2e 69 6e 2f 74 72 61 63 6b 65 72 2f 73 63 72 69 70 74 73 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 cybercoprahul.in/tracker/scripts/upload.php
		$a_00_2 = {73 65 6e 64 5f 73 6e 61 70 2e 70 68 70 3f 69 64 3d } //1 send_snap.php?id=
		$a_00_3 = {73 65 6e 64 5f 73 6d 73 6c 69 73 74 2e 70 68 70 3f 69 64 3d } //1 send_smslist.php?id=
		$a_00_4 = {2f 2e 74 72 61 63 6b 65 72 2f 2e 66 69 6c 65 73 } //2 /.tracker/.files
		$a_00_5 = {73 2e 77 68 61 74 73 61 70 70 2e 6e 65 74 } //1 s.whatsapp.net
		$a_00_6 = {70 6f 74 65 6e 74 69 61 6c 6c 79 20 68 61 72 6d 66 75 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 68 61 73 20 62 65 65 6e 20 64 65 74 65 63 74 65 64 } //1 potentially harmful application has been detected
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}