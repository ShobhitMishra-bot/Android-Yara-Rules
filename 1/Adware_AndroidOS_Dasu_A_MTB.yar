
rule Adware_AndroidOS_Dasu_A_MTB{
	meta:
		description = "Adware:AndroidOS/Dasu.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {10 00 54 31 [0-10] 21 00 22 00 [0-06] 00 00 1a 01 [0-06] 10 00 54 31 [0-10] 21 00 22 00 [0-06] 00 00 22 00 [0-06] 00 00 1a 01 [0-06] 10 00 54 31 } //1
		$a_01_1 = {54 78 77 70 33 50 49 66 59 5a 42 71 58 2f 45 52 51 6b 64 35 78 42 78 46 30 58 51 } //1 Txwp3PIfYZBqX/ERQkd5xBxF0XQ
		$a_01_2 = {63 6f 6d 2f 6c 6f 61 64 65 72 2f 61 63 74 69 76 69 74 79 2f 50 41 } //1 com/loader/activity/PA
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_4 = {67 65 74 52 75 6e 6e 69 6e 67 54 61 73 6b 73 } //1 getRunningTasks
		$a_01_5 = {73 65 74 41 75 74 6f 43 61 6e 63 65 6c } //1 setAutoCancel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}