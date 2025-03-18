
rule Trojan_AndroidOS_Banker_AA_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 79 6a 64 6c 73 6f 66 74 2e 6d 74 72 73 76 } //1 com.yjdlsoft.mtrsv
		$a_01_1 = {70 72 65 5f 6b 65 79 5f 73 65 72 76 65 72 5f 75 72 6c } //1 pre_key_server_url
		$a_01_2 = {70 72 65 5f 6b 65 79 5f 70 72 69 5f 6b 65 79 } //1 pre_key_pri_key
		$a_01_3 = {70 72 65 5f 6b 65 79 5f 73 65 72 76 65 72 5f 69 6e 64 65 78 } //1 pre_key_server_index
		$a_01_4 = {70 72 65 5f 6b 65 79 5f 73 65 63 75 72 69 74 79 5f 70 61 63 6b 61 67 65 } //1 pre_key_security_package
		$a_01_5 = {66 38 37 65 66 33 35 33 62 66 34 36 63 65 61 32 37 35 66 39 65 38 39 33 35 35 30 62 39 31 61 39 } //1 f87ef353bf46cea275f9e893550b91a9
		$a_01_6 = {65 37 39 37 64 31 36 65 63 30 37 30 62 66 65 64 34 36 36 63 39 61 36 65 34 61 38 34 30 33 37 35 } //1 e797d16ec070bfed466c9a6e4a840375
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}