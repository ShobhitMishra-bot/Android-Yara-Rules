
rule Adware_AndroidOS_Peterhodkinsoner_A{
	meta:
		description = "Adware:AndroidOS/Peterhodkinsoner.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 65 74 65 72 68 6f 64 6b 69 6e 73 6f 6e 65 72 } //2 peterhodkinsoner
		$a_00_1 = {4c 67 4d 4e 42 77 30 48 41 67 51 56 55 77 59 59 42 77 39 42 48 68 45 45 46 31 59 4a 45 68 49 53 51 78 63 56 55 77 67 53 41 67 55 56 55 77 73 5a 42 6c 59 52 45 68 59 44 54 51 3d 3d } //2 LgMNBw0HAgQVUwYYBw9BHhEEF1YJEhISQxcVUwgSAgUVUwsZBlYREhYDTQ==
		$a_00_2 = {4c 68 63 4e 46 51 73 46 44 68 4d 46 55 77 63 62 44 41 55 45 55 78 51 57 47 68 6f 4f 45 67 42 58 44 78 4d 50 46 42 41 66 51 78 6b 48 55 31 56 5a } //2 LhcNFQsFDhMFUwcbDAUEUxQWGhoOEgBXDxMPFBAfQxkHU1VZ
		$a_00_3 = {4c 68 63 56 45 41 77 53 45 56 67 51 42 67 73 44 42 69 51 45 41 77 67 57 41 42 4d 4d 46 67 6f 44 53 78 6f 49 42 77 45 46 41 68 70 49 } //1 LhcVEAwSEVgQBgsDBiQEAwgWABMMFgoDSxoIBwEFAhpI
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=7
 
}