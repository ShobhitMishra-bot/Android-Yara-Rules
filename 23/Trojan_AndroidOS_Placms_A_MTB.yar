
rule Trojan_AndroidOS_Placms_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Placms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 6d 5f 70 61 79 } //1 mm_pay
		$a_03_1 = {4c 63 6f 6d [0-14] 50 61 79 53 74 61 74 75 73 } //1
		$a_00_2 = {64 65 62 75 67 5f 62 6f 6f 74 5f 70 61 79 } //1 debug_boot_pay
		$a_01_3 = {49 73 63 68 65 63 6b 4e 75 6d 62 65 72 } //1 IscheckNumber
		$a_00_4 = {73 70 2f 73 65 6e 64 6e 75 6d 2e 78 6d 6c } //1 sp/sendnum.xml
		$a_01_5 = {4b 49 4c 4c 20 53 4d 53 20 49 53 20 4f 4b } //1 KILL SMS IS OK
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}