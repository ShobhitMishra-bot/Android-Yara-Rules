
rule HackTool_AndroidOS_Mesploit_C_MTB{
	meta:
		description = "HackTool:AndroidOS/Mesploit.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 41 70 70 6c 69 63 61 74 69 6f 6e 53 70 6c 69 74 74 65 64 53 68 65 6c 6c } //1 ClientApplicationSplittedShell
		$a_01_1 = {53 4f 2d 38 38 35 39 2d 31 } //5 SO-8859-1
		$a_01_2 = {67 65 74 63 6c 69 70 64 61 74 61 } //1 getclipdata
		$a_01_3 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 getClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}