package com.example.insecure

import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

/**
 * 刻意不安全的 fixture。不要抄。
 * 對應 MAST-NETWORK-001/002/003。
 */
object NetworkClient {

    // MAST-NETWORK-003：空的 TrustManager，任何憑證都通過
    private val trustAllCerts = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    // MAST-NETWORK-003：主機名驗證形同虛設
    private val allowAllHostnames = HostnameVerifier { _: String, _: SSLSession -> true }

    fun insecureContext(): SSLContext =
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustAllCerts), java.security.SecureRandom())
        }

    // MAST-NETWORK-001：明文端點
    const val BASE_URL = "http://api.example.com/v1"
}
