rule BaDoink : official_android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - Android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:
		$type_a_1 = "6589y459gj4058rt" ascii
		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD" ascii
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg" ascii

	condition:
		$type_a_1 or
		all of ($type_b*)
}
