rule Android_Malware_Boxersms {
    meta:
        description = "Detects potential indicators of Android malware"
        author = "Shobhit"
        date = "2025-01-24"
        reference = "http://androids-market.ru/register/"
    
    strings:
        $network_operator = "android.telephony.TelephonyManager.getNetworkOperator"
        $receiver_class = "com.software.application.C2DMReceiver"
        $sms_data_key = "SMS_DATA_KEY"
        $sms_data_value = "2535+11527+x+a"
        $pref1 = "PREF1"
        $pref1_value = "78344"
        $pref2 = "PREF2"

    condition:
        all of ($network_operator, $receiver_class, $sms_data_key, $sms_data_value, $pref1, $pref1_value, $pref2)
}
