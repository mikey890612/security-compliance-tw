package com.example.insecure

import android.app.Activity
import android.database.sqlite.SQLiteDatabase
import android.os.Bundle
import android.text.InputType
import android.webkit.WebView
import android.widget.EditText

/**
 * 刻意不安全的 fixture。不要抄。
 * 對應 MAST-PLATFORM-002/007、MAST-CODE-001/002。
 * 另刻意缺席：Root 偵測（RESILIENCE-001）、螢幕覆蓋防護（PLATFORM-006）。
 */
class MainActivity : Activity() {

    private lateinit var db: SQLiteDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // MAST-PLATFORM-002：WebView 設定全開
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.allowFileAccess = true
        web.settings.allowUniversalAccessFromFileURLs = true
        WebView.setWebContentsDebuggingEnabled(true)
        web.addJavascriptInterface(this, "bridge")
        web.loadUrl("http://example.com/")

        // MAST-PLATFORM-007：敏感輸入未關閉鍵盤快取
        val idField = EditText(this)
        idField.inputType = InputType.TYPE_CLASS_TEXT
        idField.hint = "身分證字號"

        // MAST-CODE-001：深層連結參數未驗證
        val orderId = intent.data?.getQueryParameter("id")
        search(orderId ?: "")
    }

    // MAST-CODE-002：本機 SQLite 字串拼接
    fun search(keyword: String) {
        db.rawQuery("SELECT * FROM notes WHERE title LIKE '%$keyword%'", null)
        db.execSQL("DELETE FROM notes WHERE owner = '$keyword'")
    }

    // MAST-PLATFORM-002：橋接方法暴露給任意載入的頁面
    @android.webkit.JavascriptInterface
    fun getToken(): String = AuthManager.API_KEY
}
