
rule Ransom_AndroidOS_Filecoder_B{
	meta:
		description = "Ransom:AndroidOS/Filecoder.B,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 6f 77 20 63 61 6e 20 74 68 65 79 20 70 75 74 20 79 6f 75 72 20 70 68 6f 74 6f 20 69 6e 20 74 68 69 73 20 61 70 70 2c 20 49 20 74 68 69 6e 6b 20 49 20 6e 65 65 64 20 74 6f 20 74 65 6c 6c 20 79 6f 75 } //2 how can they put your photo in this app, I think I need to tell you
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 65 76 78 2e 78 79 7a 2f 70 6f 73 74 2e 70 68 70 3f 75 69 64 3d } //2 http://wevx.xyz/post.php?uid=
		$a_00_2 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 20 63 6f 70 79 20 63 6f 6d 70 6c 65 74 65 64 } //2 Bitcoin address copy completed
		$a_00_3 = {55 73 65 72 49 44 20 63 6f 70 79 20 63 6f 6d 70 6c 65 74 65 64 } //2 UserID copy completed
		$a_00_4 = {6c 75 63 6b 79 73 65 76 65 6e } //2 luckyseven
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}