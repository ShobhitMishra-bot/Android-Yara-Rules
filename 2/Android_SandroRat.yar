rule SandroRat
{
    meta:
        author = "Jacob Soo Lead Re"
        date = "21-May-2016"
        description = "This rule detects SandroRat based on activity names."
        source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

    strings:
        $activity_name = "net.droidjack.server"

    condition:
        $activity_name
}
