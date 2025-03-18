
rule Trojan_AndroidOS_Autolycos_A{
	meta:
		description = "Trojan:AndroidOS/Autolycos.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 50 51 69 42 65 78 54 77 47 41 38 55 65 56 35 38 55 30 36 68 50 33 53 66 4e 77 58 42 53 48 41 76 57 4f 74 73 4b 6c 33 30 71 45 51 6b 31 44 36 64 76 54 70 34 33 68 54 31 55 33 62 4f 69 37 43 } //1 NPQiBexTwGA8UeV58U06hP3SfNwXBSHAvWOtsKl30qEQk1D6dvTp43hT1U3bOi7C
		$a_01_1 = {4a 61 76 61 5f 63 6f 6d 5f 6f 6b 63 61 6d 65 72 61 5f 66 75 6e 6e 79 5f 6d 61 69 6e 5f 75 69 5f 46 75 6e 6e 79 43 61 6d 65 72 61 41 70 70 5f 69 6e 69 74 41 70 70 } //1 Java_com_okcamera_funny_main_ui_FunnyCameraApp_initApp
		$a_00_2 = {ec 33 40 f9 ec 57 80 b9 ee 27 40 f9 b7 16 80 52 59 09 80 52 d1 69 6c 38 e0 1f 40 f9 f3 33 40 b9 00 c8 73 38 f3 02 31 0a 31 02 19 0a 71 02 11 2a f3 02 20 0a 00 00 19 0a 60 02 00 2a 11 00 11 4a d1 69 2c 38 ac 02 00 d0 ae 02 00 d0 b1 02 00 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}