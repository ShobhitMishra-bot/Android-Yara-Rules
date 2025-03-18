rule BankBot_Polish_Banks
{
    meta:
        author = "Eternal"
        hash0 = "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
        description = "BankBot/Mazain attacking Polish banks"
        reference = "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/"
        
    strings:
        // Bank-related identifiers
        $bank1 = "com.comarch.mobile"
        $bank2 = "eu.eleader.mobilebanking.pekao"
        $bank3 = "eu.eleader.mobilebanking.raiffeisen"
        $bank4 = "pl.fmbank.smart"
        $bank5 = "pl.mbank"
        $bank6 = "wit.android.bcpBankingApp.millenniumPL"
        $bank7 = "pl.pkobp.iko"
        $bank8 = "pl.plus.plusonline"
        $bank9 = "pl.ing.mojeing"
        $bank10 = "pl.bzwbk.bzwbk24"
        $bank11 = "com.getingroup.mobilebanking"
        $bank12 = "eu.eleader.mobilebanking.invest"
        $bank13 = "pl.bph"
        $bank14 = "com.konylabs.cbplpat"
        $bank15 = "eu.eleader.mobilebanking.pekao.firm"

        // General strings
        $s1 = "IMEI"
        $s2 = "/:/"
        $s3 = "p="
        $s4 = "SMS From:"

        // Permissions as strings
        $perm_internet = "android.permission.INTERNET"
        $perm_wakelock = "android.permission.WAKE_LOCK"
        $perm_read_ext = "android.permission.READ_EXTERNAL_STORAGE"
        $perm_receive_mms = "android.permission.RECEIVE_MMS"
        $perm_read_sms = "android.permission.READ_SMS"
        $perm_receive_sms = "android.permission.RECEIVE_SMS"

    condition:
        all of ($s*) and 1 of ($bank*) and 
        all of ($perm_*)
}
