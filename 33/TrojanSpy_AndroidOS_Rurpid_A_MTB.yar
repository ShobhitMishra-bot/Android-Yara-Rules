
rule TrojanSpy_AndroidOS_Rurpid_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Rurpid.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 2f 72 75 62 2f 73 79 73 73 65 63 } //1 de/rub/syssec
		$a_01_1 = {63 6f 6d 2e 73 6f 6d 65 2e 77 68 65 72 65 2e 6c 6f 63 6b 2e 73 74 61 74 69 63 } //1 com.some.where.lock.static
		$a_01_2 = {70 72 65 70 61 72 65 53 65 6e 64 } //1 prepareSend
		$a_01_3 = {73 65 6e 64 44 61 74 61 } //1 sendData
		$a_01_4 = {31 32 37 2e 30 2e 30 2e 31 3a 35 33 34 37 31 } //1 127.0.0.1:53471
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}