
rule Trojan_AndroidOS_VolterSms_A{
	meta:
		description = "Trojan:AndroidOS/VolterSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 74 65 72 53 4d 53 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //1 AlterSMSActivity.java
		$a_01_1 = {2f 61 70 69 2f 67 65 74 5f 6f 73 73 2f } //1 /api/get_oss/
		$a_01_2 = {53 4d 53 5f 44 45 4c 49 56 45 52 45 44 } //1 SMS_DELIVERED
		$a_03_3 = {4c 63 6f 6d 2f (61 6c 74 65 72|76 6f 6c 74 65) 2f 73 6d 73 2f 52 24 73 74 72 69 6e 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}