rule Android_Tordow
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"

	strings:
		$package_name = "com.di2.two"
		$activity_1 = "API2Service"
		$activity_2 = "CryptoUtil"
		$activity_3 = "Loader"
		$activity_4 = "Logger"

		$cert_sha1_1 = "78F162D2CC7366754649A806CF17080682FE538C"
		$cert_sha1_2 = "BBA26351CE41ACBE5FA84C9CF331D768CEDD768F"
		$cert_sha1_3 = "0B7C3BC97B6D7C228F456304F5E1B75797B7265E"

	condition:
		// Match package name or activities and permissions or specific certificates
		$package_name or
		all of ($activity_*) or
		($cert_sha1_1 or $cert_sha1_2 or $cert_sha1_3)
}
