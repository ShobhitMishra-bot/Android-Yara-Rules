
rule TrojanSpy_AndroidOS_Raddex_GV_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Raddex.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 63 68 61 74 5f 61 70 70 5f 73 65 63 75 72 69 69 33 37 37 32 30 32 31 } //2 com/example/chat_app_securii3772021
		$a_01_1 = {43 43 4d 79 49 6e 41 64 6d 69 6e 43 68 65 63 6b } //1 CCMyInAdminCheck
		$a_00_2 = {23 23 23 20 52 41 54 20 69 73 20 4b 69 6c 6c 65 64 20 23 23 23 } //1 ### RAT is Killed ###
		$a_00_3 = {41 75 39 64 69 6f 53 74 72 6d 72 } //1 Au9dioStrmr
		$a_00_4 = {2f 61 70 69 2f 70 75 62 6c 69 63 5f 6c 6f 67 69 6e 5f 6e 65 77 2f } //1 /api/public_login_new/
		$a_00_5 = {48 6d 7a 43 6e 74 63 74 73 32 33 35 } //1 HmzCntcts235
		$a_00_6 = {4c 6f 63 4d 53 47 39 32 33 35 32 31 } //1 LocMSG923521
		$a_00_7 = {52 61 64 64 69 78 5f } //1 Raddix_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}