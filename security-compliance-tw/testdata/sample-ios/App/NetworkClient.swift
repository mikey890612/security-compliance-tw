import Foundation

/// 刻意不安全的 fixture。不要抄。
/// 對應 MAST-NETWORK-001/002/003。
final class NetworkClient: NSObject, URLSessionDelegate {

    // MAST-NETWORK-001：明文端點
    static let baseURL = "http://api.example.com/v1"

    lazy var session: URLSession = {
        URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }()

    // MAST-NETWORK-003：無條件信任任何伺服器憑證
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let trust = challenge.protectionSpace.serverTrust!
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
