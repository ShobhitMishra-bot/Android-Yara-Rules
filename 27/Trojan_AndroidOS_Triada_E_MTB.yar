
rule Trojan_AndroidOS_Triada_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Triada.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 74 42 74 42 74 52 65 63 65 69 76 65 72 } //1 rtBtBtReceiver
		$a_01_1 = {63 68 6a 69 65 73 65 72 76 69 63 65 } //1 chjieservice
		$a_01_2 = {74 65 73 74 36 2e 6c 6f 67 } //1 test6.log
		$a_01_3 = {2f 64 65 76 2f 73 6f 63 6b 65 74 2f 64 6f 67 2e 73 6f 63 6b } //1 /dev/socket/dog.sock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}