
rule Trojan_AndroidOS_Piom_RT{
	meta:
		description = "Trojan:AndroidOS/Piom.RT,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 75 73 74 6f 6d 65 72 6c 6f 76 65 73 75 70 70 6f 72 74 2e 63 6f 6d 2f 61 70 69 2f 61 70 70 2f 6d 65 73 73 61 67 65 } //1 customerlovesupport.com/api/app/message
		$a_01_1 = {6d 65 73 73 61 67 65 53 65 6e 74 20 74 6f } //1 messageSent to
		$a_01_2 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 63 75 73 74 6f 6d 65 72 73 75 70 70 6f 72 74 32 } //1 com.example.customersupport2
		$a_01_3 = {39 42 31 41 31 39 42 32 37 39 32 44 35 39 35 36 38 41 44 36 44 45 36 31 32 31 32 44 46 33 44 47 34 32 45 38 46 35 33 38 37 43 41 36 33 42 31 31 } //1 9B1A19B2792D59568AD6DE61212DF3DG42E8F5387CA63B11
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}