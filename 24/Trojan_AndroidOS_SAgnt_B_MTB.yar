
rule Trojan_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 6d 73 63 2e 6d 6f 6e 74 65 72 6e 65 74 2e 63 6f 6d } //1 mmsc.monternet.com
		$a_00_1 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_00_2 = {73 65 6e 64 54 6f 53 65 72 76 65 72 53 6d 73 } //1 sendToServerSms
		$a_00_3 = {67 65 74 50 6f 6e 65 } //1 getPone
		$a_00_4 = {67 65 74 53 6d 73 63 42 79 49 6d 73 69 } //1 getSmscByImsi
		$a_00_5 = {53 6d 73 50 61 79 4d 6f 64 65 6c } //1 SmsPayModel
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}