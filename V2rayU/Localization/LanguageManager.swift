//
//  LanguageManager.swift
//  V2rayU
//
//  Created by yanue on 2025/8/30.
//

import SwiftUI

enum Language: String, CaseIterable, Identifiable {
    var id: Self { self }
    case en = "English"

    var localeIdentifier: String {
        return "en"
    }

    init(localeIdentifier: String) {
        self = .en
    }
}

// 在 LanguageManager 中添加
extension Notification.Name {
    static let languageDidChange = Notification.Name("LanguageDidChange")
}

// MARK: - Language Manager
@MainActor
class LanguageManager: ObservableObject {
    static let shared = LanguageManager()

    @Published var selectedLanguage: Language {
        didSet {
            UserDefaults.standard.set([selectedLanguage.localeIdentifier], forKey: "AppleLanguages")
            UserDefaults.standard.synchronize()
            applyLanguage()
        }
    }

    private var languageBundle: Bundle?
    @Published private(set) var currentLocale: Locale

    private init() {
        self.selectedLanguage = .en
        self.currentLocale = Locale(identifier: "en")

        if let path = Bundle.main.path(forResource: "en", ofType: "lproj"),
           let bundle = Bundle(path: path) {
            self.languageBundle = bundle
        } else {
            self.languageBundle = Bundle.main
        }
    }

    /// 切换语言时调用
    private func applyLanguage() {
        if let path = Bundle.main.path(forResource: selectedLanguage.localeIdentifier, ofType: "lproj"),
           let bundle = Bundle(path: path) {
            languageBundle = bundle
        } else {
            languageBundle = Bundle.main
        }
        currentLocale = Locale(identifier: selectedLanguage.localeIdentifier)

        // ⚠️ 注意：这里不要直接调用 AppMenuManager.shared
        // 否则可能导致初始化循环
        // 建议在 AppDelegate 或 SceneDelegate 中监听语言变化后再更新菜单
        NotificationCenter.default.post(name: .languageDidChange, object: nil)
    }

    func localizedString(_ key: String) -> String {
        return languageBundle?.localizedString(forKey: key, value: nil, table: nil) ?? key
    }
}

// MARK: - String 扩展
extension String {
    @MainActor
    init(localized key: String) {
        self = LanguageManager.shared.localizedString(key)
    }
    @MainActor
    init(localized label: LanguageLabel) {
        self = LanguageManager.shared.localizedString(label.rawValue)
    }
    @MainActor
    init(localized label: LanguageLabel, arguments: CVarArg...) {
        let localizedString = LanguageManager.shared.localizedString(label.rawValue)
        let finalString = arguments.isEmpty ? localizedString : String(format: localizedString, arguments: arguments)
        self = finalString
    }
}


// MARK: - View Extensions
extension View {
    /// 响应式本地化 Text - 使用字符串
    func localized(_ label: String) -> some View {
        LocalizedTextView(key: label)
    }
    
    /// 响应式本地化 Text - 使用枚举
    func localized(_ label: LanguageLabel) -> some View {
        LocalizedTextView(key: label.rawValue)
    }
    
    /// 响应式本地化 Text - 带参数
    func localized(_ label: LanguageLabel, _ arguments: CVarArg...) -> some View {
        LocalizedTextView(key: label.rawValue, arguments: arguments)
    }
    
    /// 获取本地化字符串（用于 Picker 标题等）
    func localizedString(_ label: LanguageLabel) -> String {
        LanguageManager.shared.localizedString(label.rawValue)
    }
}

// MARK: - 响应式本地化 Text View
struct LocalizedTextView: View {
    let key: String
    var arguments: [CVarArg] = []
    
    @StateObject private var languageManager = LanguageManager.shared

    var body: some View {
        let localizedString = languageManager.localizedString(key)
        let finalString = arguments.isEmpty ? localizedString : String(format: localizedString, arguments: arguments)
        Text(finalString)
    }
}

// MARK: - 响应式本地化 Text View - 使用枚举(View外部调用更方便)
struct LocalizedTextLabelView: View {
    let label: LanguageLabel
    
    @StateObject private var languageManager = LanguageManager.shared

    var body: some View {
        let localizedString = languageManager.localizedString(label.rawValue)
        Text(localizedString)
    }
}
