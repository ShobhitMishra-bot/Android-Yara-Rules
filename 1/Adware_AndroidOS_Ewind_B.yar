
rule Adware_AndroidOS_Ewind_B{
	meta:
		description = "Adware:AndroidOS/Ewind.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6e 61 67 65 72 2f 6c 6f 63 6b 73 63 72 65 65 6e 2f 4c 6f 63 6b 73 63 72 65 65 6e 4d 61 6e 61 67 65 72 49 6d 70 6c } //1 manager/lockscreen/LockscreenManagerImpl
		$a_01_1 = {73 74 61 72 74 53 63 72 65 65 6e 52 65 63 65 69 76 65 72 } //1 startScreenReceiver
		$a_01_2 = {75 6e 6c 6f 63 6b 41 64 44 65 74 65 63 74 6f 72 } //1 unlockAdDetector
		$a_01_3 = {73 64 6b 2f 73 65 72 76 69 63 65 2f 64 65 74 65 63 74 6f 72 2f 44 65 74 65 63 74 6f 72 } //1 sdk/service/detector/Detector
		$a_01_4 = {73 68 6f 77 4c 6f 63 6b 73 63 72 65 65 6e 41 64 54 61 73 6b 46 61 63 74 6f 72 79 } //1 showLockscreenAdTaskFactory
		$a_01_5 = {43 72 79 6f 70 69 67 67 79 41 70 70 6c 69 63 61 74 69 6f 6e } //1 CryopiggyApplication
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}