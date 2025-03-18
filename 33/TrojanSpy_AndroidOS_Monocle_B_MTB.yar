
rule TrojanSpy_AndroidOS_Monocle_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Monocle.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 45 76 65 6e 74 } //1 onAccessibilityEvent
		$a_00_1 = {6b 65 79 6c 6f 67 5f 6d 65 73 73 65 6e 67 65 72 } //1 keylog_messenger
		$a_00_2 = {4e 6f 74 69 66 79 4d 65 73 73 65 6e 67 65 72 } //1 NotifyMessenger
		$a_00_3 = {4f 74 68 65 72 4e 6f 74 69 66 79 } //1 OtherNotify
		$a_00_4 = {6b 65 79 6c 6f 67 5f 6f 74 68 65 72 } //1 keylog_other
		$a_00_5 = {41 70 70 65 6e 64 4c 69 6e 65 4c 6f 6e 67 43 6c 69 63 6b 4d } //1 AppendLineLongClickM
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}