
rule Trojan_AndroidOS_OpFakeSms_A_MTB{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 61 75 79 66 67 6b 36 6f 6c 62 78 63 73 36 6f 6c 62 78 63 73 37 6b 76 6e 6c 65 66 6d 37 65 6f 6a 77 77 62 79 36 6c 79 62 66 6f 78 36 6c 79 62 66 6f 78 37 62 6f 67 70 61 63 63 37 77 79 74 73 70 6f 6e 36 70 64 6d 64 74 61 36 70 64 6d 64 74 61 38 70 75 65 63 6f 63 77 69 37 6c 79 61 70 6f 63 77 38 6b 68 71 6f 67 75 76 6c 38 71 75 63 71 78 72 62 75 36 6f 6c 62 78 63 73 36 6c 79 62 66 6f 78 37 70 6f 79 68 6c 65 79 36 6c 79 62 66 6f 78 } //1 6auyfgk6olbxcs6olbxcs7kvnlefm7eojwwby6lybfox6lybfox7bogpacc7wytspon6pdmdta6pdmdta8puecocwi7lyapocw8khqoguvl8qucqxrbu6olbxcs6lybfox7poyhley6lybfox
		$a_01_1 = {37 62 6f 67 70 61 63 63 36 6c 79 6e 6c 6e 74 37 6b 76 6e 6c 65 66 6d 36 72 78 6d 64 64 61 36 70 64 6d 64 74 61 38 70 75 65 63 6f 63 77 69 37 67 76 62 70 78 75 63 38 76 77 61 69 68 6f 75 76 36 70 64 6d 64 74 61 36 61 6f 73 6e 66 66 } //1 7bogpacc6lynlnt7kvnlefm6rxmdda6pdmdta8puecocwi7gvbpxuc8vwaihouv6pdmdta6aosnff
		$a_01_2 = {76 63 6c 63 67 6b 66 67 37 6b 70 6b 77 71 62 66 36 6a 6c 66 6d 64 70 37 6b 70 6b 77 71 62 66 } //1 vclcgkfg7kpkwqbf6jlfmdp7kpkwqbf
		$a_01_3 = {37 6b 70 6b 77 71 62 66 36 61 75 79 66 67 6b 37 71 72 65 78 6e 64 75 38 73 65 79 61 74 61 77 6e 36 6f 6c 62 78 63 73 38 6f 76 69 70 76 74 6e 79 38 78 61 68 74 78 6c 78 74 36 6f 6c 62 78 63 73 38 66 72 68 68 71 79 6c 6d 38 72 71 6c 6b 73 75 6f 6c 37 6b 68 65 65 76 77 61 37 70 6f 79 68 6c 65 79 37 6b 70 6b 77 71 62 66 36 6f 6c 62 78 63 73 } //1 7kpkwqbf6auyfgk7qrexndu8seyatawn6olbxcs8ovipvtny8xahtxlxt6olbxcs8frhhqylm8rqlksuol7kheevwa7poyhley7kpkwqbf6olbxcs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}