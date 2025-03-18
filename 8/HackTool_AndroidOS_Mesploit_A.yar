
rule HackTool_AndroidOS_Mesploit_A{
	meta:
		description = "HackTool:AndroidOS/Mesploit.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f } //2 Lcom/metasploit/stage/
		$a_00_1 = {2f 50 61 79 6c 6f 61 64 3b } //2 /Payload;
		$a_01_2 = {2e 64 65 78 00 04 2e 6a 61 72 00 01 2f 00 01 3a } //1 搮硥Ѐ樮牡Ā/㨁
		$a_01_3 = {70 61 79 6c 6f 61 64 2e 64 65 78 00 0b 70 61 79 6c 6f 61 64 2e 6a 61 72 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}