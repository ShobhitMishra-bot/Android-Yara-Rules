
rule TrojanSpy_AndroidOS_ActionSpy_A{
	meta:
		description = "TrojanSpy:AndroidOS/ActionSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 69 73 79 6a 76 2f 6b 6c 78 62 6c 6e 77 63 } //10 com/isyjv/klxblnwc
		$a_01_1 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 63 6d 64 6c 69 6e 65 } //5 /proc/self/cmdline
		$a_01_2 = {65 78 70 6f 72 74 20 4c 44 5f 4c 49 42 52 41 52 59 5f 50 41 54 48 3d 2f 76 65 6e 64 6f 72 2f 6c 69 62 3a 2f 73 79 73 74 65 6d 2f 6c 69 62 } //5 export LD_LIBRARY_PATH=/vendor/lib:/system/lib
		$a_01_3 = {70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //1 pm install -r
		$a_00_4 = {4d 69 63 72 6f 6c 6f 67 } //1 Microlog
		$a_01_5 = {73 70 5f 73 65 72 76 65 72 } //1 sp_server
		$a_01_6 = {73 70 5f 75 75 69 64 } //1 sp_uuid
		$a_01_7 = {4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 43 30 63 58 33 6c 30 37 39 4a 49 48 32 49 37 47 30 53 6e 45 4a 32 52 35 38 75 79 68 31 70 65 68 34 73 6a 75 } //1 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cX3l079JIH2I7G0SnEJ2R58uyh1peh4sju
		$a_01_8 = {2f 2e 75 74 73 6b 2f 63 6f 6e 66 2f } //1 /.utsk/conf/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=16
 
}