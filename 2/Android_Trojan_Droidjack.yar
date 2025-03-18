rule Trojan_Droidjack
{
	meta:
		author = "https://twitter.com/SadFud75"
		description = "Detects Droidjack Trojan based on known package names and activity strings"
	
	strings:
		$package_name = "net.droidjack.server"
		$activity_name = "net.droidjack.server"

	condition:
		$package_name or $activity_name
}
