import UIKit

/// 刻意不安全的 fixture。不要抄。
/// 對應 MAST-PLATFORM-003/007。
/// 另刻意缺席：越獄偵測（RESILIENCE-001）。
final class LoginViewController: UIViewController {

    private let idField = UITextField()
    private let pwdField = UITextField()

    override func viewDidLoad() {
        super.viewDidLoad()

        // MAST-PLATFORM-007：敏感輸入未關閉鍵盤快取與自動修正
        idField.placeholder = "身分證字號"
        idField.autocorrectionType = .yes

        pwdField.placeholder = "密碼"
        pwdField.isSecureTextEntry = false

        // 未檢查越獄跡象即載入敏感畫面
        loadWallet()
    }

    // MAST-PLATFORM-003：權杖放進系統剪貼簿
    func copyToken(_ token: String) {
        UIPasteboard.general.string = token
    }

    private func loadWallet() {}
}
