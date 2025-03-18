
rule Trojan_AndroidOS_Hiddapp_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddapp.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 /api.telegram.org/bot
		$a_00_1 = {2f 73 65 6e 64 6d 65 73 73 61 67 65 } //1 /sendmessage
		$a_00_2 = {61 63 63 2e 74 78 74 } //1 acc.txt
		$a_00_3 = {2f 72 61 74 2f 75 70 6c 6f 61 64 5f 66 69 6c 65 2e 70 68 70 } //1 /rat/upload_file.php
		$a_00_4 = {62 34 61 2e 65 78 61 6d 70 6c 65 2e 62 6f 74 63 6f 6e 74 72 69 6c } //1 b4a.example.botcontril
		$a_00_5 = {6e 75 6d 62 65 72 73 2e 74 78 74 } //1 numbers.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}