
rule Worm_AndroidOS_Jimoke_B{
	meta:
		description = "Worm:AndroidOS/Jimoke.B,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 49 73 53 70 61 72 74 61 54 68 69 73 49 73 53 70 61 72 74 61 } //5 ThisIsSpartaThisIsSparta
		$a_01_1 = {61 53 49 53 4b 53 62 68 46 4c 59 45 2f 62 39 44 45 42 53 37 64 2f 54 41 6f 2f 4c 36 2b 37 4a 57 66 30 33 6a 32 33 73 39 78 42 79 73 37 41 51 56 49 6b 75 65 45 31 4a 2b 30 4a 56 77 64 62 62 67 56 71 39 55 4c 38 4f 58 4b 61 53 4f 71 34 39 59 30 77 4f 33 7a 76 46 79 78 71 47 4c 44 31 6c 54 37 69 32 6d 46 74 67 67 57 69 4c 62 56 73 4a 65 31 51 48 55 62 70 79 6e 46 47 66 46 6e 6b 45 55 6b 71 70 73 6e 76 57 56 6e 55 77 67 64 2f 32 43 66 59 55 49 55 54 48 67 2f 4b 79 58 33 58 52 41 65 34 76 51 58 50 6c 34 74 79 39 38 30 53 59 44 44 4f 45 31 78 67 3d 3d } //5 aSISKSbhFLYE/b9DEBS7d/TAo/L6+7JWf03j23s9xBys7AQVIkueE1J+0JVwdbbgVq9UL8OXKaSOq49Y0wO3zvFyxqGLD1lT7i2mFtggWiLbVsJe1QHUbpynFGfFnkEUkqpsnvWVnUwgd/2CfYUIUTHg/KyX3XRAe4vQXPl4ty980SYDDOE1xg==
		$a_01_2 = {44 45 53 65 64 65 } //5 DESede
		$a_01_3 = {53 45 4e 44 49 47 20 6d 53 47 20 74 6f 20 69 6e } //1 SENDIG mSG to in
		$a_01_4 = {4c 63 6f 6d 2f 62 65 6e 73 74 6f 6b 65 73 2f 70 61 74 68 61 6b 73 63 68 6f 6f 6b } //1 Lcom/benstokes/pathakschook
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}