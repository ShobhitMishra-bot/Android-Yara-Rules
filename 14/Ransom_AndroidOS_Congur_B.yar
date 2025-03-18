
rule Ransom_AndroidOS_Congur_B{
	meta:
		description = "Ransom:AndroidOS/Congur.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 68 65 42 65 67 69 6e 54 69 6d 65 54 6f 46 69 6e 69 73 68 } //2 theBeginTimeToFinish
		$a_00_1 = {6b 65 79 54 6f 75 74 68 49 6e 74 } //2 keyTouthInt
		$a_00_2 = {74 6b 2e 6a 69 61 6e 6d 6f 2e 6c 6f 63 6b 70 68 6f 6e 65 } //1 tk.jianmo.lockphone
		$a_00_3 = {63 6f 6d 2e 79 63 2e 6c 6f 76 65 6c 6f 63 6b } //1 com.yc.lovelock
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}