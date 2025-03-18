
rule TrojanSpy_AndroidOS_CoockStealer_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/CoockStealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 43 6f 6f 6b 69 65 73 54 6f 54 65 6c 65 67 72 61 6d } //1 sendCookiesToTelegram
		$a_03_1 = {07 a1 07 b2 71 ?? ?? 00 00 00 0c 07 07 28 6e 20 ?? ?? 87 00 0c 07 07 74 07 47 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0a 07 38 07 15 00 07 07 54 77 ?? ?? 07 48 71 20 ?? ?? 87 00 0c 07 07 75 07 57 38 07 09 00 07 07 54 77 ?? ?? 07 58 } //1
		$a_03_2 = {07 9c 1a 0d ?? ?? 07 8e 12 1f 46 0e 0e 0f 6e 10 ?? ?? 0e 00 0c 0e 6e 30 ?? ?? dc 0e 0c 0c 07 9c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0c 0c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0a 0c 38 0c 39 00 07 9c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0c 0c 07 0d 54 dd ?? ?? 1a 0e ?? ?? 1a 0f ?? ?? 72 30 ?? ?? ed 0f 0c 0d 6e 20 ?? ?? dc 00 0a 0c 38 0c 07 00 12 0c 1f 0c ?? ?? 07 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}