rule Android_AliPay_smsStealer
{
	meta:
		description = "Yara rule for detection of Fake AliPay SMS Stealer"
		sample = "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
		source = "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
		ref = "https://analyst.koodous.com/rulesets/1192"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "START_SERVICE"
		$str_2 = "extra_key_sms"
		$str_3 = "android.provider.Telephony.SMS_RECEIVED"
		$str_4 = "mPhoneNumber"

	condition:
		all of ($str_*)
}
