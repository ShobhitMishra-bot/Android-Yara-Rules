
rule Trojan_AndroidOS_SpyFakeCalls_A{
	meta:
		description = "Trojan:AndroidOS/SpyFakeCalls.A,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_00_0 = {7c 2a 74 65 6c 45 6e 74 69 74 79 41 72 72 61 79 4c 69 73 74 2a 7c } //5 |*telEntityArrayList*|
		$a_00_1 = {7c 2a 63 61 6c 6c 45 6e 74 69 74 79 2a 7c } //5 |*callEntity*|
		$a_00_2 = {7c 2a 61 70 6b 45 6e 74 69 74 79 2a 7c } //5 |*apkEntity*|
		$a_00_3 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //1 uploadCallLog
		$a_00_4 = {75 70 6c 6f 61 64 44 65 76 69 63 65 49 6e 66 6f } //1 uploadDeviceInfo
		$a_00_5 = {75 70 6c 6f 61 64 52 65 63 6f 72 64 69 6e 67 46 69 6c 65 } //1 uploadRecordingFile
		$a_00_6 = {75 70 64 61 74 65 43 6f 6d 6d 61 6e 64 52 65 63 6f 72 64 69 6e 67 53 74 61 74 75 73 } //1 updateCommandRecordingStatus
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=16
 
}