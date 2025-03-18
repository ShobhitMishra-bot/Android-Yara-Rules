rule Android_OmniRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "Detects OmniRat malware in Android APKs"
		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"

	strings:
		$a = "android.engine.apk" // Common file reference in OmniRat
		$activity = "com.app.MainActivity"
		$permission = "android.permission.WRITE_EXTERNAL_STORAGE"
		$package_name = "com.app"

	condition:
		$a and $activity and $permission and $package_name
}
