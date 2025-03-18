rule spyAgent
{
    meta:
        description = "This rule detects Arabian spyware which records calls and gathers user information sent to a remote C&C server."
        sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
        reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
        author = "@koodous_project"

    strings:
        $phone = "0597794205"
        $caption = "New victim arrived"
        $cc_1 = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
        $cc_2 = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
        $cc_3 = "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
        $cc_4 = "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
        $cc_5 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
        $cc_6 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
        $cc_7 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
        $cc_8 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"

    condition:
        any of ($cc_*) or ($phone and $caption)
}
