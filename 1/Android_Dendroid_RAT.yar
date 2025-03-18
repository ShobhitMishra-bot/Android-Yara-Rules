rule Android_Dendroid
{
	meta:
		author = "https://twitter.com/jsmesa"
		date = "19-May-2016"
		description = "Detects Dendroid RAT malware in Android APKs"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"
		reference = "https://koodous.com/"

	strings:
		// Static patterns commonly found in Dendroid RAT
		$s1 = "/upload-pictures.php?"
		$s2 = "Opened Dialog:"
		$s3 = "com/connect/MyService"
		$s4 = "android/os/Binder"
		$s5 = "android/app/Service"
		$s6 = "Droidian"
		$s7 = "DroidianService"
		$s8 = "ServiceReceiver"
		$s9 = "Dendroid"

	condition:
		// Trigger if multiple Dendroid-related patterns are found
		all of ($s1, $s2, $s3, $s4, $s5) or
		all of ($s6, $s7) or
		all of ($s8, $s9)
}
