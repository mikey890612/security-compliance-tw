package com.example.insecure

import android.content.Context
import android.util.Log
import java.security.MessageDigest
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 刻意不安全的 fixture。不要抄。
 * 對應 MAST-STORAGE-001/002/004、MAST-CRYPTO-001/002/003、MAST-AUTH-001。
 */
class AuthManager(private val context: Context) {

    companion object {
        // MAST-STORAGE-004：硬編碼機密
        const val API_KEY = "FIXTURE-NOT-A-REAL-KEY-0000000000"
        const val JWT_SECRET = "FIXTURE-NOT-A-REAL-SECRET-000000"

        // MAST-CRYPTO-003：寫死的對稱金鑰與 IV
        private val AES_KEY = "0123456789abcdef".toByteArray()
        private val AES_IV = ByteArray(16)
    }

    // MAST-STORAGE-001：權杖明文寫進 SharedPreferences
    fun saveToken(token: String) {
        val prefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
        prefs.edit().putString("access_token", token).apply()

        // MAST-STORAGE-002：敏感資料寫進日誌
        Log.d("AuthManager", "saved token=$token apiKey=$API_KEY")
    }

    // MAST-CRYPTO-001：已破解的雜湊演算法用於密碼
    fun hashPassword(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    // MAST-CRYPTO-002：非密碼學安全的亂數用於交談識別碼與 OTP
    fun newSessionId(): String = Random().nextLong().toString()

    fun newOtp(): Int = Random().nextInt(900000) + 100000

    // MAST-CRYPTO-003：固定金鑰 + 固定 IV
    fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(AES_KEY, "AES"), IvParameterSpec(AES_IV))
        return cipher.doFinal(plain)
    }

    // MAST-AUTH-001／003：用戶端自行裁決是否放行
    fun isAdmin(): Boolean =
        context.getSharedPreferences("auth", Context.MODE_PRIVATE)
            .getBoolean("is_admin", false)

    fun deleteUser(targetId: String) {
        if (isAdmin()) {
            Log.d("AuthManager", "deleting $targetId")
        }
    }
}
