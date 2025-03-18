
rule Trojan_AndroidOS_Thamera_A{
	meta:
		description = "Trojan:AndroidOS/Thamera.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 57 78 73 62 33 63 67 63 47 56 79 62 57 6c 7a 63 32 6c 76 62 69 42 30 62 79 42 6a 62 32 35 30 61 57 35 31 5a 51 3d } //1 QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ=
		$a_01_1 = {57 56 63 31 61 32 4e 74 4f 58 42 61 51 7a 56 33 59 32 30 35 4d 6d 46 58 55 6d 78 6a 61 54 56 56 57 6c 64 34 62 47 4e 48 61 48 5a 69 62 6d 74 31 56 54 41 78 56 46 67 78 53 6b 5a 52 4d 46 5a 4b 56 6d 74 57 52 51 } //1 WVc1a2NtOXBaQzV3Y205MmFXUmxjaTVVWld4bGNHaHZibmt1VTAxVFgxSkZRMFZKVmtWRQ
		$a_01_2 = {4c 6d 46 6a 64 47 6c 32 61 58 52 70 5a 58 4d 75 55 33 42 73 59 58 4e 6f 51 57 4e 30 61 58 5a 70 64 48 6b 75 51 6d 78 68 59 32 74 55 61 47 56 74 5a 51 } //1 LmFjdGl2aXRpZXMuU3BsYXNoQWN0aXZpdHkuQmxhY2tUaGVtZQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}