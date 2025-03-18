rule Android_GenericSMS_Fraud
{
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        description = "Detects Android SMS fraud activities"
        sample1 = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
        sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"
        sample3 = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
        sample4 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
        sample5 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

    strings:
        $sha1_1 = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
        $sha1_2 = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
        $sha1_3 = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
        $url = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
        $pitchfork = "pitchfork=022D4"
        $triangle = "NotLeftTriangleEqual=022EC"
        $vector_base = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
        $code = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"

    condition:
        all of ($sha1_1, $sha1_2, $sha1_3, $url, $pitchfork, $triangle, $vector_base, $code)
}
