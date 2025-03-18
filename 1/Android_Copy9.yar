rule Android_Copy9
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "Detects commercial spyware from Copy9"
		source = "http://copy9.com/"

	strings:
		// Static patterns found in Copy9 spyware
		$str_1 = "com.ispyoo"               // Package name
		$str_2 = "com.ispyoo.service"       // Service name
		$str_3 = "com.ispyoo.receiver"      // Receiver name
		$str_4 = "copy9"                    // Reference to the spyware name

	condition:
		any of ($str_*)
}
