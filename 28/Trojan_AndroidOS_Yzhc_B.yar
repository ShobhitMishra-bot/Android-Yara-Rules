
rule Trojan_AndroidOS_Yzhc_B{
	meta:
		description = "Trojan:AndroidOS/Yzhc.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {2b 38 36 31 33 38 30 30 37 35 35 35 30 30 } //1 +8613800755500
		$a_01_1 = {38 30 38 30 2f 63 6c 69 65 6e 74 2f 6c 6f 67 67 69 6e 67 61 6c 6c 2e 70 68 70 3f } //1 8080/client/loggingall.php?
		$a_01_2 = {62 75 73 69 6e 65 73 73 6e 75 6d 62 65 72 } //1 businessnumber
		$a_01_3 = {73 70 6e 75 6d 63 6f 64 65 } //1 spnumcode
		$a_01_4 = {35 31 77 69 64 67 65 74 73 2e 63 6f 6d 2f 73 73 2f 73 65 72 76 69 63 65 2f 61 63 74 69 6f 6e 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 49 73 53 75 63 63 65 73 73 } //1 51widgets.com/ss/service/action.php?action=IsSuccess
		$a_01_5 = {73 65 74 59 65 61 68 } //1 setYeah
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}