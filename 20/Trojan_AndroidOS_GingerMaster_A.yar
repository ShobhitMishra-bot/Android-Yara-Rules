
rule Trojan_AndroidOS_GingerMaster_A{
	meta:
		description = "Trojan:AndroidOS/GingerMaster.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 20 53 64 43 61 72 64 2c 20 43 61 6e 27 74 20 52 75 6e 21 } //1 No SdCard, Can't Run!
		$a_01_1 = {4d 79 48 61 6c 6c 3a 3a 6f 6e 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 65 64 } //1 MyHall::onServiceConnected
		$a_03_2 = {63 6c 69 65 6e 74 2e (67 6f 33 36 30 64 61 79 73|6d 75 73 74 6d 6f 62 69 6c 65) 2e 63 6f 6d 2f 63 6c 69 65 6e 74 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 73 6f 66 74 26 73 6f 66 74 5f 69 64 3d } //1
		$a_01_3 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 67 61 6d 65 5f 73 65 72 76 69 63 65 5f 64 6f 77 6e 6c 6f 61 64 20 6f 72 64 65 72 20 62 79 20 73 6f 66 74 5f 69 64 20 64 65 73 63 } //1 select * from game_service_download order by soft_id desc
		$a_01_4 = {67 61 6d 65 5f 73 65 72 76 69 63 65 5f 64 6f 77 6e 6c 6f 61 64 64 62 2e 64 62 } //1 game_service_downloaddb.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}