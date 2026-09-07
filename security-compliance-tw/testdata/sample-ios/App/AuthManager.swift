import CommonCrypto
import Foundation

/// 刻意不安全的 fixture。不要抄。
/// 對應 MAST-STORAGE-001/002/004、MAST-CRYPTO-001/002。
final class AuthManager {

    // MAST-STORAGE-004：硬編碼機密
    static let apiKey = "FIXTURE-NOT-A-REAL-KEY-0000000000"
    static let jwtSecret = "FIXTURE-NOT-A-REAL-SECRET-000000"

    // MAST-STORAGE-001：權杖明文寫進 UserDefaults
    func save(token: String) {
        UserDefaults.standard.set(token, forKey: "access_token")
        UserDefaults.standard.set(Self.apiKey, forKey: "api_key")

        // MAST-STORAGE-002：敏感資料寫進日誌
        print("saved token=\(token)")
        NSLog("apiKey=%@", Self.apiKey)
    }

    // MAST-CRYPTO-001：已破解的雜湊演算法
    func hashPassword(_ password: String) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Data(password.utf8)
        _ = data.withUnsafeBytes {
            CC_MD5($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }

    // MAST-CRYPTO-002：非密碼學安全的亂數
    func newSessionId() -> String {
        String(arc4random())
    }

    func newOtp() -> Int {
        Int(arc4random_uniform(900_000)) + 100_000
    }
}
