
rule Trojan_AndroidOS_SmsHider_A{
	meta:
		description = "Trojan:AndroidOS/SmsHider.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {78 6d 73 74 73 76 2e 63 6f 6d 2f (4e 6f 74 69 63 65|55 70 64 61 74 65) 2f } //1
		$a_01_1 = {6a 2e 53 4d 53 48 69 64 65 72 2e 4d 61 69 6e 53 65 72 76 69 63 65 } //1 j.SMSHider.MainService
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}