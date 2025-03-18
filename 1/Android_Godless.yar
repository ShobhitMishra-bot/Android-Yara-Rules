rule Android_Godlike
{
    meta:
        author = "Jacob Soo Lead Re"
        date = "01-July-2016"
        description = "Detects Android malware leveraging local and remote exploits, including Godlike samples."
        source = "http://blog.trendmicro.com/trendlabs-security-intelligence/godless-mobile-malware-uses-multiple-exploits-root-devices/"

    strings:
        // Local exploit indicators
        $local_1 = "libgodlikelib.so"

        // Remote exploit indicators
        $remote_1 = "libroot.so"
        $remote_2 = "silent91_arm_bin.root"
        $remote_3 = "libr.so"
        $remote_4 = "libpl_droidsonroids_gif.so"

        // Service and receiver indicators as strings
        $service_fast_install = "FastInstallService"
        $service_download = "DownloadService"
        $receiver_godlike = "godlike.e"

    condition:
        (
            // Local exploit detection
            $local_1 or
            ($service_fast_install and $service_download and $receiver_godlike)
        ) or
        (
            // Remote exploit detection
            any of ($remote_1, $remote_2, $remote_3, $remote_4)
        )
}
