
rule Backdoor_AndroidOS_Coudw_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Coudw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 63 6c 6f 75 64 73 2f 73 65 72 76 65 72 2f 53 68 43 6d 64 } //2 Lcom/clouds/server/ShCmd
		$a_00_1 = {73 68 65 6c 6c 63 6d 64 } //1 shellcmd
		$a_00_2 = {73 79 73 74 65 6d 2f 62 69 6e 2f 70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //1 system/bin/pm install -r
		$a_00_3 = {6d 6f 75 6e 74 20 2d 6f 20 72 65 6d 6f 75 6e 74 2c 72 77 20 2f 73 79 73 74 65 6d } //1 mount -o remount,rw /system
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}