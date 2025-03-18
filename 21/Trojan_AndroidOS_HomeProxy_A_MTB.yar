
rule Trojan_AndroidOS_HomeProxy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/HomeProxy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 70 69 6e 67 2d 61 70 6b 3f 69 64 3d } //1 /api/ping-apk?id=
		$a_00_1 = {7a 69 70 5f 66 69 6c 65 2e 63 6f 6d 6d 65 6e 74 } //1 zip_file.comment
		$a_00_2 = {2f 52 65 73 74 61 72 74 53 65 72 76 69 63 65 52 65 63 65 69 76 65 72 3b } //1 /RestartServiceReceiver;
		$a_00_3 = {73 6f 63 6b 73 5f 70 61 73 73 77 6f 72 64 } //1 socks_password
		$a_00_4 = {68 69 64 64 65 6e 5f 69 63 6f 6e } //1 hidden_icon
		$a_00_5 = {0e 7b 22 72 65 73 75 6c 74 22 3a 22 33 22 7d 00 } //1 笎爢獥汵≴∺∳}
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}