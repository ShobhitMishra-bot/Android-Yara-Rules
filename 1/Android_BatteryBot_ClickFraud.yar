rule BatteryBotPro_ClickFraud
{
	meta:
		description = "Detects fake BatteryBotPro engaging in click fraud, ad fraud, SMS sending, or trojan-like behavior"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
		author = "https://twitter.com/fdrg21"
		reference = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"

	strings:
		// Static patterns commonly found in malicious BatteryBotPro variants
		$str_activity = "com.polaris.BatteryIndicatorPro.BatteryInfoActivity"
		$str_ad_fraud = "clickfraud" // Example: keyword indicating ad fraud
		$str_fake_package = "BatteryBotPro"

	condition:
		any of ($str_activity, $str_ad_fraud, $str_fake_package)
}

