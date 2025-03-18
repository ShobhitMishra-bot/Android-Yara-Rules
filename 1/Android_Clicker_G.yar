rule Android_Clicker_G
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "Detects Clicker.G malware samples"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"

	strings:
		$a = "upd.php?text="               // Common hardcoded URL fragment
		$b = "MyBroadCastReceiver"         // Hardcoded class name for the receiver
		$c = "android.intent.action.BOOT_COMPLETED" // Intent for auto-starting after boot

	condition:
		$a and ($b or $c)
}
