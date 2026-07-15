import Foundation

enum XrayCapabilityKind: String, CaseIterable, Codable {
    case inboundProtocol = "Inbound"
    case outboundProtocol = "Outbound"
    case transportMethod = "Transport"
    case transportSecurity = "Security"
    case additionalConfig = "Additional"
    case flow = "Flow"
}

enum CapabilityRulesCore: String, Codable {
    case xray
    case singbox = "sing-box"

    var bundledFileName: String {
        switch self {
        case .xray:
            return "xray-capability-rules"
        case .singbox:
            return "singbox-capability-rules"
        }
    }
}

enum CapabilityRuleStatus: String, Codable {
    case supported
    case legacy
    case compatibility
    case unsupported
    case removed
    case pendingReview
}

enum CapabilityRuleAppSupportLevel: String, Codable {
    case supported
    case advisory
    case unsupported
}

struct CapabilityRuleAppSupport: Codable {
    let level: CapabilityRuleAppSupportLevel
    let note: String
}

struct CapabilityEvidence: Codable {
    let id: String
    let kind: String
    let statement: String
    let sourceTitle: String
    let sourceURL: String
    let sourceVersion: String?
    let sourceDate: String?
    let quote: String
    let reviewedAt: String?
    let note: String?

    private enum CodingKeys: String, CodingKey {
        case id
        case kind
        case statement
        case sourceTitle
        case sourceVersion
        case sourceDate
        case quote
        case reviewedAt
        case note
        case sourceURL
    }

    private enum LegacyCodingKeys: String, CodingKey {
        case sourceURL
    }

    private enum SnakeCaseCodingKeys: String, CodingKey {
        case sourceURL = "source_url"
    }

    // JSONDecoder.keyDecodingStrategy = .convertFromSnakeCase 会把
    // JSON 中的 `source_url` 转换为内部 key `sourceUrl`（注意：仅首字母大写，
    // 不是 `sourceURL`），导致默认 CodingKeys/LegacyCodingKeys/SnakeCaseCodingKeys
    // 都匹配不到，从而触发整份 JSON 解码失败。这里增加一个兜底匹配。
    private enum ConvertedSnakeCaseCodingKeys: String, CodingKey {
        case sourceURL = "sourceUrl"
    }

    init(id: String, kind: String, statement: String, sourceTitle: String, sourceURL: String, sourceVersion: String?, sourceDate: String?, quote: String, reviewedAt: String?, note: String?) {
        self.id = id
        self.kind = kind
        self.statement = statement
        self.sourceTitle = sourceTitle
        self.sourceURL = sourceURL
        self.sourceVersion = sourceVersion
        self.sourceDate = sourceDate
        self.quote = quote
        self.reviewedAt = reviewedAt
        self.note = note
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
        let snakeCaseContainer = try decoder.container(keyedBy: SnakeCaseCodingKeys.self)
        let convertedContainer = try decoder.container(keyedBy: ConvertedSnakeCaseCodingKeys.self)

        id = try container.decode(String.self, forKey: .id)
        kind = try container.decode(String.self, forKey: .kind)
        statement = try container.decode(String.self, forKey: .statement)
        sourceTitle = try container.decode(String.self, forKey: .sourceTitle)
        if let value = try snakeCaseContainer.decodeIfPresent(String.self, forKey: .sourceURL) {
            sourceURL = value
        } else if let value = try convertedContainer.decodeIfPresent(String.self, forKey: .sourceURL) {
            sourceURL = value
        } else {
            sourceURL = try legacyContainer.decode(String.self, forKey: .sourceURL)
        }
        sourceVersion = try container.decodeIfPresent(String.self, forKey: .sourceVersion)
        sourceDate = try container.decodeIfPresent(String.self, forKey: .sourceDate)
        quote = try container.decode(String.self, forKey: .quote)
        reviewedAt = try container.decodeIfPresent(String.self, forKey: .reviewedAt)
        note = try container.decodeIfPresent(String.self, forKey: .note)
    }
}

struct CapabilityRulePayload: Codable {
    let type: CapabilityRuleStatus
    let legacyMin: String?
    let calendarMin: String?
    let removedAt: String?
    let note: String
}

struct CapabilityPayload: Codable {
    let key: String
    let displayName: String
    let kind: XrayCapabilityKind
    let docsPath: String?
    let rule: CapabilityRulePayload
    let appSupport: CapabilityRuleAppSupport?
    let evidence: [CapabilityEvidence]?
}

struct CapabilityRulesDocument: Codable {
    let schemaVersion: Int
    let core: CapabilityRulesCore
    let latestReviewedVersion: String?
    let capabilities: [CapabilityPayload]
}

enum CapabilityRulesSourceKind {
    case overrideFile
    case bundledFile
    case swiftFallback
    case unavailable
}

struct CapabilityRulesStatusSnapshot {
    let core: CapabilityRulesCore
    let sourceKind: CapabilityRulesSourceKind
    let path: String?
    let latestReviewedVersion: String?
    let capabilityCount: Int
}

struct CapabilityRulesUpdateResult: Sendable {
    let targetDirectory: String
    let xrayCapabilityCount: Int
    let singboxCapabilityCount: Int

    var message: String {
        "Capability rules updated in \(targetDirectory)\nXray: \(xrayCapabilityCount), Sing-Box: \(singboxCapabilityCount)"
    }
}

enum CapabilityRulesUpdateError: LocalizedError {
    case invalidBaseURL(String)
    case unexpectedHTTPStatus(URL, Int)
    case invalidDocument(URL, String)

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL(let value):
            return "Invalid capability-rules base URL: \(value)"
        case .unexpectedHTTPStatus(let url, let statusCode):
            return "Capability rules download failed (\(statusCode)): \(url.absoluteString)"
        case .invalidDocument(let url, let reason):
            return "Invalid capability rules at \(url.absoluteString): \(reason)"
        }
    }
}

enum CapabilityRulesLoader {
    private static let bundleSubdirectory = "capability-rules"
    private static let primaryOverrideDirectoryName = "capability-rules"
    private static let supportedSchemaVersions: Set<Int> = [1, 2, 3, 4]

    // 多线程安全: PingAll 并发调用 loadDetailed，用 NSLock 保护 cache 避免 Dictionary 数据竞争
    private static let cacheLock = NSLock()
    private static nonisolated(unsafe) var cache: [CapabilityRulesCore: (document: CapabilityRulesDocument, url: URL, sourceKind: CapabilityRulesSourceKind)] = [:]

    static func load(core: CapabilityRulesCore) -> CapabilityRulesDocument? {
        loadDetailed(core: core)?.document
    }

    // 远程更新后清空 cache，保证下次读取拿到新文件
    static func invalidateCache() {
        cacheLock.withLock { cache = [:] }
    }

    /// 首次启动时把 bundle 内的 rules 拷贝到 ~/.V2rayU/capability-rules/
    /// 保证重装或清空目录后也有初始副本，避免旧版损坏文件阻塞 bundle fallback
    static func seedOverrideIfNeeded() {
        let fm = FileManager.default
        let overrideDir = URL(fileURLWithPath: overrideDirectoryPath(), isDirectory: true)
        guard !fm.fileExists(atPath: overrideDir.path) else { return }
        guard let bundleDir = Bundle.main.url(forResource: "capability-rules", withExtension: nil) else { return }

        do {
            try fm.createDirectory(at: overrideDir, withIntermediateDirectories: true)
            let items = try fm.contentsOfDirectory(at: bundleDir, includingPropertiesForKeys: nil)
            for item in items where item.pathExtension == "json" {
                let dest = overrideDir.appendingPathComponent(item.lastPathComponent)
                try fm.copyItem(at: item, to: dest)
            }
            logger.info("capability rules seeded to \(overrideDir.path)")
        } catch {
            logger.warning("capability rules seed failed: \(error.localizedDescription)")
        }
    }

    /// 启动时检查更新，7 天内只检查一次
    static func checkForUpdatesIfNeeded() {
        let autoInterval: TimeInterval = 24 * 3600
        let lastUpdate = UserDefaults.standard.double(forKey: UserDefaults.KEY.capabilityRulesUpdateDate.rawValue)
        let elapsed = Date.now.timeIntervalSince1970 - lastUpdate
        guard lastUpdate == 0 || elapsed > autoInterval else { return }

        Task {
            let trimmed = UserDefaults.get(forKey: .capabilityRulesBaseURL, defaultValue: defaultCapabilityRulesBaseURL)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let baseURL = trimmed.isEmpty ? defaultCapabilityRulesBaseURL : trimmed
            do {
                _ = try await updateFromRemote(baseURL: baseURL)
                UserDefaults.standard.set(Date.now.timeIntervalSince1970, forKey: UserDefaults.KEY.capabilityRulesUpdateDate.rawValue)
                logger.info("capability rules auto-updated from \(baseURL)")
            } catch {
                logger.warning("capability rules auto-update failed: \(error.localizedDescription)")
            }
        }
    }

    static func status(core: CapabilityRulesCore) -> CapabilityRulesStatusSnapshot {
        if let loaded = loadDetailed(core: core) {
            return CapabilityRulesStatusSnapshot(
                core: core,
                sourceKind: loaded.sourceKind,
                path: loaded.url.path,
                latestReviewedVersion: loaded.document.latestReviewedVersion,
                capabilityCount: loaded.document.capabilities.count
            )
        }

        switch core {
        case .xray:
            return CapabilityRulesStatusSnapshot(
                core: core,
                sourceKind: .swiftFallback,
                path: nil,
                latestReviewedVersion: nil,
                capabilityCount: XraySupportCatalog.builtInCapabilities.count
            )
        case .singbox:
            return CapabilityRulesStatusSnapshot(
                core: core,
                sourceKind: .unavailable,
                path: nil,
                latestReviewedVersion: nil,
                capabilityCount: 0
            )
        }
    }

    static func overrideDirectoryPath() -> String {
        URL(fileURLWithPath: AppHomePath)
            .appendingPathComponent(primaryOverrideDirectoryName, isDirectory: true)
            .path
    }

    static func updateFromRemote(baseURL: String) async throws -> CapabilityRulesUpdateResult {
        let xrayURL = try remoteRulesURL(baseURL: baseURL, fileName: CapabilityRulesCore.xray.bundledFileName)
        let singboxURL = try remoteRulesURL(baseURL: baseURL, fileName: CapabilityRulesCore.singbox.bundledFileName)

        let xray = try await downloadAndValidateRules(from: xrayURL, expectedCore: .xray)
        let singbox = try await downloadAndValidateRules(from: singboxURL, expectedCore: .singbox)

        let targetDirectory = URL(fileURLWithPath: overrideDirectoryPath(), isDirectory: true)
        try FileManager.default.createDirectory(at: targetDirectory, withIntermediateDirectories: true)
        try xray.data.write(
            to: targetDirectory.appendingPathComponent("\(CapabilityRulesCore.xray.bundledFileName).json"),
            options: .atomic
        )
        try singbox.data.write(
            to: targetDirectory.appendingPathComponent("\(CapabilityRulesCore.singbox.bundledFileName).json"),
            options: .atomic
        )

        invalidateCache()
        UserDefaults.standard.set(Date.now.timeIntervalSince1970, forKey: UserDefaults.KEY.capabilityRulesUpdateDate.rawValue)
        return CapabilityRulesUpdateResult(
            targetDirectory: targetDirectory.path,
            xrayCapabilityCount: xray.document.capabilities.count,
            singboxCapabilityCount: singbox.document.capabilities.count
        )
    }

    private static func mergeCapabilities(override: CapabilityRulesDocument, bundled: CapabilityRulesDocument) -> CapabilityRulesDocument {
        var mergedPayloads = bundled.capabilities
        let overrideDict = Dictionary(uniqueKeysWithValues: override.capabilities.map { ($0.key, $0) })
        for (i, capability) in mergedPayloads.enumerated() {
            if let o = overrideDict[capability.key] {
                mergedPayloads[i] = o
            }
        }
        
        let bundledKeys = Set(bundled.capabilities.map { $0.key })
        for capability in override.capabilities {
            if !bundledKeys.contains(capability.key) {
                mergedPayloads.append(capability)
            }
        }

        return CapabilityRulesDocument(
            schemaVersion: override.schemaVersion,
            core: override.core,
            latestReviewedVersion: override.latestReviewedVersion,
            capabilities: mergedPayloads
        )
    }

    private static func loadDetailed(core: CapabilityRulesCore) -> (document: CapabilityRulesDocument, url: URL, sourceKind: CapabilityRulesSourceKind)? {
        if let cached = cacheLock.withLock({ cache[core] }) {
            return cached
        }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase

        let urls = candidateURLs(for: core)
        let overrideCandidate = urls.first { $0.sourceKind == .overrideFile }
        let bundleCandidate = urls.first { $0.sourceKind == .bundledFile }

        var overrideDoc: CapabilityRulesDocument?
        var overrideURL: URL?
        if let o = overrideCandidate, FileManager.default.fileExists(atPath: o.url.path) {
            do {
                let data = try Data(contentsOf: o.url)
                let doc = try decoder.decode(CapabilityRulesDocument.self, from: data)
                if supportedSchemaVersions.contains(doc.schemaVersion), doc.core == core, !doc.capabilities.isEmpty {
                    overrideDoc = doc
                    overrideURL = o.url
                }
            } catch {
                logger.warning("capability override rules load failed: \(o.url.path) error=\(error.localizedDescription)")
            }
        }

        var bundleDoc: CapabilityRulesDocument?
        var bundleURL: URL?
        if let b = bundleCandidate, FileManager.default.fileExists(atPath: b.url.path) {
            do {
                let data = try Data(contentsOf: b.url)
                let doc = try decoder.decode(CapabilityRulesDocument.self, from: data)
                if supportedSchemaVersions.contains(doc.schemaVersion), doc.core == core, !doc.capabilities.isEmpty {
                    bundleDoc = doc
                    bundleURL = b.url
                }
            } catch {
                logger.warning("capability bundle rules load failed: \(b.url.path) error=\(error.localizedDescription)")
            }
        }

        if let overrideDoc = overrideDoc, let bundleDoc = bundleDoc, let overrideURL = overrideURL {
            let merged = mergeCapabilities(override: overrideDoc, bundled: bundleDoc)
            let result = (merged, overrideURL, CapabilityRulesSourceKind.overrideFile)
            cacheLock.withLock { cache[core] = result }
            return result
        } else if let overrideDoc = overrideDoc, let overrideURL = overrideURL {
            let result = (overrideDoc, overrideURL, CapabilityRulesSourceKind.overrideFile)
            cacheLock.withLock { cache[core] = result }
            return result
        } else if let bundleDoc = bundleDoc, let bundleURL = bundleURL {
            let result = (bundleDoc, bundleURL, CapabilityRulesSourceKind.bundledFile)
            cacheLock.withLock { cache[core] = result }
            return result
        }

        return nil
    }

    private static func candidateURLs(for core: CapabilityRulesCore) -> [(url: URL, sourceKind: CapabilityRulesSourceKind)] {
        var urls: [(url: URL, sourceKind: CapabilityRulesSourceKind)] = []
        let fileName = core.bundledFileName

        let overrideURL = URL(fileURLWithPath: AppHomePath)
            .appendingPathComponent(primaryOverrideDirectoryName, isDirectory: true)
            .appendingPathComponent("\(fileName).json", isDirectory: false)
        urls.append((overrideURL, .overrideFile))

        if let bundleURL = Bundle.main.url(forResource: fileName, withExtension: "json", subdirectory: bundleSubdirectory) {
            urls.append((bundleURL, .bundledFile))
        }

        return urls
    }

    private static func remoteRulesURL(baseURL: String, fileName: String) throws -> URL {
        let trimmed = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let separator = trimmed.hasSuffix("/") ? "" : "/"
        guard let url = URL(string: "\(trimmed)\(separator)\(fileName).json"),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else {
            throw CapabilityRulesUpdateError.invalidBaseURL(baseURL)
        }
        return url
    }

    private static func downloadAndValidateRules(from url: URL, expectedCore: CapabilityRulesCore) async throws -> (data: Data, document: CapabilityRulesDocument) {
        var request = URLRequest(url: url)
        request.timeoutInterval = 30
        let (data, response) = try await URLSession.shared.data(for: request)
        if let httpResponse = response as? HTTPURLResponse,
           !(200..<300).contains(httpResponse.statusCode) {
            throw CapabilityRulesUpdateError.unexpectedHTTPStatus(url, httpResponse.statusCode)
        }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let document = try decoder.decode(CapabilityRulesDocument.self, from: data)
        try validateRemoteDocument(document, expectedCore: expectedCore, sourceURL: url)
        return (data, document)
    }

    private static func validateRemoteDocument(_ document: CapabilityRulesDocument, expectedCore: CapabilityRulesCore, sourceURL: URL) throws {
        guard supportedSchemaVersions.contains(document.schemaVersion) else {
            throw CapabilityRulesUpdateError.invalidDocument(sourceURL, "schemaVersion must be 1, 2, 3, or 4")
        }
        guard document.core == expectedCore else {
            throw CapabilityRulesUpdateError.invalidDocument(sourceURL, "core mismatch: \(document.core.rawValue) != \(expectedCore.rawValue)")
        }
        guard !document.capabilities.isEmpty else {
            throw CapabilityRulesUpdateError.invalidDocument(sourceURL, "capabilities must be a non-empty array")
        }
        for (index, capability) in document.capabilities.enumerated() {
            if let evidence = capability.evidence, evidence.isEmpty {
                throw CapabilityRulesUpdateError.invalidDocument(sourceURL, "capability[\(index)].evidence must be non-empty when present")
            }
        }
    }
}

enum XrayFeatureAvailability {
    case supported
    case advisory(reason: String)
    case unsupported(reason: String)
    case unknown(reason: String)
}

struct XraySupportRule {
    let status: CapabilityRuleStatus
    let legacyMin: XrayVersion?
    let calendarMin: XrayVersion?
    let removedAt: XrayVersion?
    let note: String

    static func supported(note: String, legacyMin: XrayVersion? = nil, calendarMin: XrayVersion? = nil, removedAt: XrayVersion? = nil) -> XraySupportRule {
        XraySupportRule(status: .supported, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt, note: note)
    }

    static func legacy(note: String, legacyMin: XrayVersion? = nil, calendarMin: XrayVersion? = nil, removedAt: XrayVersion? = nil) -> XraySupportRule {
        XraySupportRule(status: .legacy, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt, note: note)
    }

    static func compatibility(note: String, legacyMin: XrayVersion? = nil, calendarMin: XrayVersion? = nil, removedAt: XrayVersion? = nil) -> XraySupportRule {
        XraySupportRule(status: .compatibility, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt, note: note)
    }

    static func removed(note: String, legacyMin: XrayVersion? = nil, calendarMin: XrayVersion? = nil, removedAt: XrayVersion? = nil) -> XraySupportRule {
        XraySupportRule(status: .removed, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt, note: note)
    }

    static func pendingReview(note: String) -> XraySupportRule {
        XraySupportRule(status: .pendingReview, legacyMin: nil, calendarMin: nil, removedAt: nil, note: note)
    }


    func describe() -> String {
        let statusText: String
        switch status {
        case .supported:
            statusText = "Currently supported features in mainline"
        case .legacy:
            statusText = "Historical / compatibility features"
        case .compatibility:
            statusText = "Compatibility mapping features"
        case .unsupported:
            statusText = "Unsupported features for the current app/core combination"
        case .removed:
            statusText = "Removed features"
        case .pendingReview:
            statusText = "Features pending review"
        }

        var parts: [String] = [statusText]
        if let legacyMin {
            parts.append("Legacy semantic version >= \(legacyMin.description)")
        }
        if let calendarMin {
            parts.append("Calendar date version >= \(calendarMin.description)")
        }
        if let removedAt {
            parts.append("< \(removedAt.description)")
        }
        return "\(parts.joined(separator: "，"))。\(note)"
    }

    func evaluate(version: XrayVersion?, featureName: String) -> XrayFeatureAvailability {
        if let boundaryResult = evaluateVersionBounds(version: version, featureName: featureName) {
            return boundaryResult
        }

        switch status {
        case .supported, .compatibility:
            return .supported
        case .legacy:
            return .advisory(reason: note)
        case .unsupported:
            return .unsupported(reason: note)
        case .removed:
            if let version, let removedAt {
                return .advisory(reason: "\(featureName) is marked as removed in newer versions (>= \(removedAt.description)); current version \(version.description) may still be available. \(note)")
            }
            return .unsupported(reason: "\(featureName) has been marked as removed by current compatibility rules. \(note)")
        case .pendingReview:
            return .advisory(reason: note)
        }
    }

    private func evaluateVersionBounds(version: XrayVersion?, featureName: String) -> XrayFeatureAvailability? {
        guard legacyMin != nil || calendarMin != nil || removedAt != nil else {
            return nil
        }
        guard let version else {
            return .unknown(reason: "Cannot identify current Xray-core version, unable to determine version bounds for \(featureName). \(note)")
        }
        if let removedAt, version >= removedAt {
            let removalText = status == .removed ? "has been removed" : "is deprecated in current compatibility rules"
            return .unsupported(reason: "\(featureName) in Xray-core \(version.description) falls within the restricted range (>= \(removedAt.description)), this feature \(removalText). \(note)")
        }
        if version.isCalendarStyle {
            if let calendarMin, version < calendarMin {
                return .unsupported(reason: "\(featureName) requires calendar date version >= \(calendarMin.description). \(note)")
            }
        } else if let legacyMin, version < legacyMin {
            return .unsupported(reason: "\(featureName) requires legacy semantic version >= \(legacyMin.description). \(note)")
        }
        return nil
    }
}

struct XrayCapabilityDefinition {
    let key: String
    let displayName: String
    let kind: XrayCapabilityKind
    let rule: XraySupportRule
    let docsPath: String?
    let evidence: [CapabilityEvidence]

    init(key: String, displayName: String, kind: XrayCapabilityKind, rule: XraySupportRule, docsPath: String?, evidence: [CapabilityEvidence] = []) {
        self.key = key
        self.displayName = displayName
        self.kind = kind
        self.rule = rule
        self.docsPath = docsPath
        self.evidence = evidence
    }
}

extension XraySupportRule {
    init?(payload: CapabilityRulePayload) {
        let legacyMin = payload.legacyMin.flatMap(XrayVersion.init)
        let calendarMin = payload.calendarMin.flatMap(XrayVersion.init)
        let removedAt = payload.removedAt.flatMap(XrayVersion.init)
        switch payload.type {
        case .supported:
            self = .supported(note: payload.note, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt)
        case .legacy:
            self = .legacy(note: payload.note, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt)
        case .compatibility:
            self = .compatibility(note: payload.note, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt)
        case .unsupported:
            self = XraySupportRule(status: .unsupported, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt, note: payload.note)
        case .removed:
            self = .removed(note: payload.note, legacyMin: legacyMin, calendarMin: calendarMin, removedAt: removedAt)
        case .pendingReview:
            self = .pendingReview(note: payload.note)
        }
    }
}

extension XrayCapabilityDefinition {
    init?(payload: CapabilityPayload) {
        guard let rule = XraySupportRule(payload: payload.rule) else {
            return nil
        }
        self.init(
            key: payload.key,
            displayName: payload.displayName,
            kind: payload.kind,
            rule: rule,
            docsPath: payload.docsPath,
            evidence: payload.evidence ?? []
        )
    }
}

struct XrayCompatibilityIssue {
    let capability: XrayCapabilityDefinition
    let availability: XrayFeatureAvailability

    var isBlocking: Bool {
        switch availability {
        case .unsupported, .unknown:
            return true
        case .supported, .advisory:
            return false
        }
    }

    var message: String {
        switch availability {
        case .supported:
            return ""
        case .advisory(let reason):
            return "• [Notice][\(capability.kind.rawValue)] \(capability.displayName): \(reason)"
        case .unsupported(let reason):
            return "• [Incompatible][\(capability.kind.rawValue)] \(capability.displayName): \(reason)"
        case .unknown(let reason):
            return "• [Pending][\(capability.kind.rawValue)] \(capability.displayName): \(reason)"
        }
    }
}

struct XrayCoreCompatibilityDecision {
    let coreType: CoreType
    let warningMessage: String?
    let issues: [XrayCompatibilityIssue]
    let canLaunch: Bool

    /// 兼容此配置所需的最小核心版本（从 blocking issue 的规则中提取）
    var minimumRequiredVersion: String? {
        let blocking = issues.filter { $0.isBlocking }
        switch coreType {
        case .XrayCore:
            let versions = blocking.compactMap { $0.capability.rule.legacyMin }
            return versions.max()?.description
        case .SingBox:
            let versions = blocking.compactMap { $0.capability.rule.legacyMin }
            return versions.max()?.description
        }
    }
}

enum SingboxFallbackCompatibility {
    static func incompatibilityReasons(for profile: ProfileEntity) -> [String] {
        SingboxFallbackResolver.incompatibilityReasons(for: profile)
    }
}

enum XraySupportCatalog {
    static let builtInCapabilities: [XrayCapabilityDefinition] = [
        // MARK: Inbound protocols
        XrayCapabilityDefinition(key: "inbound.tunnel", displayName: "Tunnel (dokodemo-door) inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/tunnel.html"),
        XrayCapabilityDefinition(key: "inbound.http", displayName: "HTTP inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/http.html"),
        XrayCapabilityDefinition(key: "inbound.shadowsocks", displayName: "Shadowsocks inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/shadowsocks.html"),
        XrayCapabilityDefinition(key: "inbound.socks", displayName: "SOCKS inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/socks.html"),
        XrayCapabilityDefinition(key: "inbound.trojan", displayName: "Trojan inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/trojan.html"),
        XrayCapabilityDefinition(key: "inbound.vless", displayName: "VLESS inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/vless.html"),
        XrayCapabilityDefinition(key: "inbound.vmess", displayName: "VMess inbound", kind: .inboundProtocol, rule: .supported(note: "Visible in official inbound protocol list."), docsPath: "/config/inbounds/vmess.html"),
        XrayCapabilityDefinition(key: "inbound.wireguard", displayName: "WireGuard inbound", kind: .inboundProtocol, rule: .supported(note: "Explicitly listed in current official inbound protocol list."), docsPath: "/config/inbounds/wireguard.html"),
        XrayCapabilityDefinition(key: "inbound.hysteria", displayName: "Hysteria2 inbound", kind: .inboundProtocol, rule: .supported(note: "Explicitly listed in current official inbound protocol list."), docsPath: "/config/inbounds/hysteria.html"),
        XrayCapabilityDefinition(key: "inbound.tun", displayName: "TUN inbound", kind: .inboundProtocol, rule: .supported(note: "Explicitly listed in current official inbound protocol list."), docsPath: "/config/inbounds/tun.html"),

        XrayCapabilityDefinition(key: "inbound.mixed", displayName: "Mixed (HTTP+SOCKS) inbound", kind: .inboundProtocol, rule: .supported(note: "Xray-core official inbound protocol list does not list mixed type, but the code has supported it as a socks alias since v24.12.31 (commit 5af9068). Verified via Build/tests/test-mixed-inbound.sh: v1.8.4~v24.12.18 reports unknown config id: mixed, v24.12.31+ accepts it.", calendarMin: XrayVersion(24, 12, 31)), docsPath: nil),

        // MARK: Outbound protocols
        XrayCapabilityDefinition(key: "outbound.blackhole", displayName: "Blackhole outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/blackhole.html"),
        XrayCapabilityDefinition(key: "outbound.dns", displayName: "DNS outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/dns.html"),
        XrayCapabilityDefinition(key: "outbound.freedom", displayName: "Freedom outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/freedom.html"),
        XrayCapabilityDefinition(key: "outbound.http", displayName: "HTTP outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/http.html"),
        XrayCapabilityDefinition(key: "outbound.loopback", displayName: "Loopback outbound", kind: .outboundProtocol, rule: .supported(note: "Explicitly listed in current official outbound protocol list."), docsPath: "/config/outbounds/loopback.html"),
        XrayCapabilityDefinition(key: "outbound.shadowsocks", displayName: "Shadowsocks outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/shadowsocks.html"),
        XrayCapabilityDefinition(key: "outbound.socks", displayName: "SOCKS outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/socks.html"),
        XrayCapabilityDefinition(key: "outbound.trojan", displayName: "Trojan outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/trojan.html"),
        XrayCapabilityDefinition(key: "outbound.vless", displayName: "VLESS outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/vless.html"),
        XrayCapabilityDefinition(key: "outbound.vmess", displayName: "VMess outbound", kind: .outboundProtocol, rule: .supported(note: "Visible in official outbound protocol list."), docsPath: "/config/outbounds/vmess.html"),
        XrayCapabilityDefinition(key: "outbound.anytls", displayName: "AnyTLS outbound", kind: .outboundProtocol, rule: XraySupportRule(status: .unsupported, legacyMin: nil, calendarMin: nil, removedAt: nil, note: "V2rayU currently does not implement config generation for Xray-core AnyTLS outbound; automatically choosing sing-box."), docsPath: nil),
        XrayCapabilityDefinition(key: "outbound.naive", displayName: "Naive outbound", kind: .outboundProtocol, rule: XraySupportRule(status: .unsupported, legacyMin: nil, calendarMin: nil, removedAt: nil, note: "Xray-core/V2rayU currently does not implement config generation for naive outbound; automatically choosing sing-box."), docsPath: nil),
        XrayCapabilityDefinition(key: "outbound.ssh", displayName: "SSH outbound", kind: .outboundProtocol, rule: XraySupportRule(status: .unsupported, legacyMin: nil, calendarMin: nil, removedAt: nil, note: "Xray-core does not support SSH outbound; automatically choosing sing-box."), docsPath: nil),
        XrayCapabilityDefinition(key: "outbound.wireguard", displayName: "WireGuard outbound", kind: .outboundProtocol, rule: .supported(note: "Explicitly listed in current official outbound protocol list."), docsPath: "/config/outbounds/wireguard.html"),
        XrayCapabilityDefinition(key: "outbound.hysteria", displayName: "Hysteria2 outbound", kind: .outboundProtocol,             rule: .supported(note: "Xray-core added hysteria2 outbound support in v26.1.23. Calendar versions < 26.1.23 are unsupported.", legacyMin: XrayVersion(9, 9, 9), calendarMin: XrayVersion(26, 1, 23)), docsPath: "/config/outbounds/hysteria.html"),

        // MARK: Transport methods
        XrayCapabilityDefinition(key: "transport.raw", displayName: "RAW transport", kind: .transportMethod, rule: .supported(note: "Visible in current official transport mainline; RAW is the new name of the former TCP transport."), docsPath: "/config/transports/raw.html"),
        XrayCapabilityDefinition(key: "transport.tcpAlias", displayName: "TCP (RAW alias)", kind: .transportMethod, rule: .compatibility(note: "V2rayU current node model uses tcp for RAW; official documentation uses RAW."), docsPath: "/config/transports/raw.html"),
        XrayCapabilityDefinition(
            key: "transport.xhttp",
            displayName: "XHTTP transport",
            kind: .transportMethod,
            rule: .supported(note: "XHTTP is stable and usable in v24.10.31 and later; early versions (v1.8.24/v24.9.30) had startup timeout defects and are excluded from the support list.", legacyMin: XrayVersion(9, 9, 9), calendarMin: XrayVersion(24, 10, 31), removedAt: nil),
            docsPath: "/config/transports/xhttp.html",
            evidence: [
                CapabilityEvidence(
                    id: "release-v25.4.30-xhttp-default-mode",
                    kind: "releaseNote",
                    statement: "Xray-core v25.4.30 release notes discuss default behavior changes for XHTTP, confirming XHTTP exists and is maintained; this evidence supports feature existence and evolution without claiming an exact release version.",
                    sourceTitle: "Xray-core v25.4.30 release notes",
                    sourceURL: "https://github.com/XTLS/Xray-core/releases/tag/v25.4.30",
                    sourceVersion: "25.4.30",
                    sourceDate: "2025-04-30",
                    quote: "XHTTP TLS default changed to packet-up, XHTTP REALITY default remains stream-one",
                    reviewedAt: "2026-05-18",
                    note: "Compiled from release analysis in this repository, source is the corresponding GitHub release page."
                )
            ]
        ),
        XrayCapabilityDefinition(key: "transport.mkcp", displayName: "mKCP transport", kind: .transportMethod, rule: .supported(note: "Starting from Xray-core v26.2.6, mKCP startup times out or ports are unavailable, indicating it was removed or needs adaptation. Legacy versions and calendar versions <= 26.1.23 work normally.", removedAt: XrayVersion(26, 2, 6)), docsPath: "/config/transports/mkcp.html"),
        XrayCapabilityDefinition(key: "transport.grpc", displayName: "gRPC transport", kind: .transportMethod, rule: .supported(note: "Still explicitly listed in the official transport mainline, so V2rayU does not consider it removed."), docsPath: "/config/transports/grpc.html"),
        XrayCapabilityDefinition(key: "transport.websocket", displayName: "WebSocket transport", kind: .transportMethod, rule: .supported(note: "Still explicitly listed in the official transport mainline, so V2rayU does not consider it removed."), docsPath: "/config/transports/websocket.html"),
        XrayCapabilityDefinition(key: "transport.httpupgrade", displayName: "HTTPUpgrade transport", kind: .transportMethod, rule: .supported(note: "Explicitly listed in current official transport mainline."), docsPath: "/config/transports/httpupgrade.html"),
        XrayCapabilityDefinition(key: "transport.hysteria", displayName: "Hysteria2 transport", kind: .transportMethod,             rule: .supported(note: "Xray-core added hysteria2 transport support in v26.1.23. Calendar versions < 26.1.23 are unsupported.", legacyMin: XrayVersion(9, 9, 9), calendarMin: XrayVersion(26, 1, 23)), docsPath: "/config/transports/hysteria.html"),

        // MARK: Legacy or compatibility items
        XrayCapabilityDefinition(key: "transport.h2", displayName: "HTTP/2 transport", kind: .transportMethod,             rule: .supported(note: "Xray-core v24.12.18 removed HTTP/2 transport, migrating to XHTTP stream-one H2 & H3. Older versions (<24.12.18) still support h2 transport.", removedAt: XrayVersion(24, 12, 18)), docsPath: "/config/transports/h2.html"),
        XrayCapabilityDefinition(key: "transport.quic", displayName: "QUIC transport", kind: .transportMethod, rule: .legacy(note: "QUIC is not in the current official transport mainline, but the site retains the history page; V2rayU only maintains legacy mapping."), docsPath: "/config/transports/quic.html"),
        XrayCapabilityDefinition(key: "transport.domainsocket", displayName: "Domain Socket transport", kind: .transportMethod, rule: .compatibility(note: "Domain Socket is not listed in the official transport mainline; V2rayU keeps compatibility mapping."), docsPath: nil),

        // MARK: Transport security / additional config
        XrayCapabilityDefinition(key: "security.none", displayName: "No extra transport security", kind: .transportSecurity, rule: .compatibility(note: "Default scenario when no TLS/REALITY is configured; not listed in official transport security mainline."), docsPath: nil),
        XrayCapabilityDefinition(key: "security.reality", displayName: "REALITY", kind: .transportSecurity, rule: .supported(note: "Explicitly listed in current official transport security mainline."), docsPath: "/config/transports/reality.html"),
        XrayCapabilityDefinition(key: "security.tls", displayName: "TLS", kind: .transportSecurity, rule: .supported(note: "Explicitly listed in current official transport security mainline."), docsPath: "/config/transports/tls.html"),
        XrayCapabilityDefinition(
            key: "security.tls.allowInsecure",
            displayName: "TLS allowInsecure",
            kind: .transportSecurity,
            rule: .removed(note: "Xray-core removed allowInsecure in 26.1.31 and hard-disabled it starting UTC 2026-06-01 00:00; use pinnedPeerCertSha256 instead (app automatically retrieves it). Failure or Hysteria2 falls back to Sing-Box.", removedAt: XrayVersion(26, 1, 31)),
            docsPath: "/config/transports/tls.html",
            evidence: [
                CapabilityEvidence(
                    id: "release-v26.2.6-allowinsecure-removed",
                    kind: "releaseNote",
                    statement: "Xray-core v26.2.6 release notes state allowInsecure is removed in favor of pinnedPeerCertSha256 / verifyPeerCertByName, with auto-disable by UTC 2026-06-01.",
                    sourceTitle: "Xray-core v26.2.6 release notes",
                    sourceURL: "https://github.com/XTLS/Xray-core/releases/tag/v26.2.6",
                    sourceVersion: "26.2.6",
                    sourceDate: "2026-02-06",
                    quote: "TLS removed the allowInsecure option, please use pinnedPeerCertSha256 and verifyPeerCertByName instead",
                    reviewedAt: "2026-06-01",
                    note: "First removed in v26.1.31; hy2 self-sign + pinnedPeerCertSha256 issue in #5655."
                )
            ]
        ),
        XrayCapabilityDefinition(key: "additional.finalmask", displayName: "FinalMask", kind: .additionalConfig, rule: .supported(note: "Explicitly listed in current official additional config mainline."), docsPath: "/config/transports/finalmask.html"),
        XrayCapabilityDefinition(key: "additional.sockopt", displayName: "Sockopt", kind: .additionalConfig, rule: .supported(note: "Explicitly listed in current official additional config mainline."), docsPath: "/config/transports/sockopt.html"),

        // MARK: Flow - app-level compatibility notes
        XrayCapabilityDefinition(key: "flow.xtls-rprx-vision", displayName: "xtls-rprx-vision flow", kind: .flow, rule: .compatibility(note: "Flow is a sub-config of VLESS/XTLS and is not listed in official transports; V2rayU does not enforce version bounds based on docs."), docsPath: "/config/inbounds/vless.html"),
        XrayCapabilityDefinition(key: "flow.xtls-rprx-vision-udp443", displayName: "xtls-rprx-vision-udp443 flow", kind: .flow, rule: .compatibility(note: "Flow is a sub-config of VLESS/XTLS and is not listed in official transports; V2rayU does not enforce version bounds based on docs."), docsPath: "/config/inbounds/vless.html")
    ]

    static func allCapabilities() -> [XrayCapabilityDefinition] {
        if let document = CapabilityRulesLoader.load(core: .xray) {
            let configured = document.capabilities.compactMap(XrayCapabilityDefinition.init(payload:))
            if !configured.isEmpty {
                return configured
            }
        }
        return builtInCapabilities
    }

    static func definitions(for kind: XrayCapabilityKind) -> [XrayCapabilityDefinition] {
        allCapabilities().filter { $0.kind == kind }
    }

    /// Check whether a specific capability is supported by the current core version
    static func isSupported(key: String) -> Bool {
        guard let definition = capability(forKey: key) else { return true }
        let version = XrayCompatibilityResolver.currentVersion()
        return evaluate(definition: definition, version: version) == nil
    }

    static func definition(forOutbound protocol: V2rayProtocolOutbound) -> XrayCapabilityDefinition? {
        switch `protocol` {
        case .freedom:
            return capability(forKey: "outbound.freedom")
        case .blackhole:
            return capability(forKey: "outbound.blackhole")
        case .dns:
            return capability(forKey: "outbound.dns")
        case .http:
            return capability(forKey: "outbound.http")
        case .socks:
            return capability(forKey: "outbound.socks")
        case .shadowsocks:
            return capability(forKey: "outbound.shadowsocks")
        case .vmess:
            return capability(forKey: "outbound.vmess")
        case .vless:
            return capability(forKey: "outbound.vless")
        case .trojan:
            return capability(forKey: "outbound.trojan")
        case .hysteria2:
            return capability(forKey: "outbound.hysteria")
        case .anytls:
            return capability(forKey: "outbound.anytls")
        case .naive:
            return capability(forKey: "outbound.naive")
        case .ssh:
            return capability(forKey: "outbound.ssh")
        }
    }

    static func definition(forTransport network: V2rayStreamNetwork) -> XrayCapabilityDefinition? {
        switch network {
        case .tcp:
            return capability(forKey: "transport.tcpAlias")
        case .kcp:
            return capability(forKey: "transport.mkcp")
        case .quic:
            return capability(forKey: "transport.quic")
        case .domainsocket:
            return capability(forKey: "transport.domainsocket")
        case .ws:
            return capability(forKey: "transport.websocket")
        case .h2:
            return capability(forKey: "transport.h2")
        case .grpc:
            return capability(forKey: "transport.grpc")
        case .xhttp:
            return capability(forKey: "transport.xhttp")
        case .hysteria2:
            return capability(forKey: "transport.hysteria")
        }
    }

    static func definition(forSecurity security: V2rayStreamSecurity) -> XrayCapabilityDefinition? {
        switch security {
        case .none:
            return capability(forKey: "security.none")
        case .tls:
            return capability(forKey: "security.tls")
        case .reality:
            return capability(forKey: "security.reality")
        case .xtls:
            return capability(forKey: "security.tls")
        }
    }

    static func definition(forFlow flow: String) -> XrayCapabilityDefinition? {
        switch flow {
        case "xtls-rprx-vision":
            return capability(forKey: "flow.xtls-rprx-vision")
        case "xtls-rprx-vision-udp443":
            return capability(forKey: "flow.xtls-rprx-vision-udp443")
        default:
            return nil
        }
    }

    static func capability(forKey key: String) -> XrayCapabilityDefinition? {
        allCapabilities().first { $0.key == key } ?? builtInCapabilities.first { $0.key == key }
    }

    static func evaluate(definition: XrayCapabilityDefinition, version: XrayVersion?) -> XrayCompatibilityIssue? {
        let availability = definition.rule.evaluate(version: version, featureName: definition.displayName)
        switch availability {
        case .supported:
            return nil
        case .advisory, .unsupported, .unknown:
            return XrayCompatibilityIssue(capability: definition, availability: availability)
        }
    }
}

enum SingboxFallbackResolver {
    private struct RequiredCapability {
        let key: String
        let displayName: String
        let kind: XrayCapabilityKind
    }

    static func incompatibilityReasons(for profile: ProfileEntity) -> [String] {
        guard let document = CapabilityRulesLoader.load(core: .singbox) else {
            return legacyFallbackReasons(for: profile)
        }

        let version = SingboxVersion(getSingboxVersion())
        let capabilities = Dictionary(uniqueKeysWithValues: document.capabilities.map { ($0.key, $0) })
        var reasons: [String] = []

        appendReasons(for: outboundRequirement(for: profile.protocol), capabilities: capabilities, version: version, reasons: &reasons)
        appendReasons(for: transportRequirement(for: profile.network), capabilities: capabilities, version: version, reasons: &reasons)
        appendReasons(for: securityRequirement(for: profile.security), capabilities: capabilities, version: version, reasons: &reasons)

        if !profile.flow.isEmpty {
            appendReasons(for: flowRequirement(for: profile.flow), capabilities: capabilities, version: version, reasons: &reasons)
        }

        if profile.network == .tcp && profile.headerType == .http {
            appendReasons(for: RequiredCapability(key: "additional.tcphttpheader", displayName: "TCP + HTTP header disguise", kind: .additionalConfig), capabilities: capabilities, version: version, reasons: &reasons)
        }

        if profile.network == .kcp {
            reasons.append("Current node uses KCP transport; Sing-Box does not support KCP and cannot automatically fall back.")
        }

        if profile.protocol == .vmess && profile.alterId > 0 {
            reasons.append("Current node uses VMess with alterId > 0 (legacy MD5 authentication), which is incompatible with Sing-Box; please change alterId to 0 (AEAD mode).")
        }

        return unique(reasons)
    }

    private static func appendReasons(for requirement: RequiredCapability?, capabilities: [String: CapabilityPayload], version: SingboxVersion?, reasons: inout [String]) {
        guard let requirement else {
            return
        }
        guard let capability = capabilities[requirement.key] else {
            reasons.append("Sing-Box capability rules do not declare [\(requirement.kind.rawValue)] \(requirement.displayName), cannot safely automatically fall back.")
            return
        }
        reasons.append(contentsOf: Self.reasons(for: capability, version: version))
    }

    private static func reasons(for capability: CapabilityPayload, version: SingboxVersion?) -> [String] {
        var reasons: [String] = []

        if let coreReason = coreBlockingReason(for: capability, version: version) {
            reasons.append(coreReason)
        }

        if let appSupport = capability.appSupport {
            switch appSupport.level {
            case .supported, .advisory:
                break
            case .unsupported:
                reasons.append("Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): \(appSupport.note)")
            }
        }

        return reasons
    }

    private static func coreBlockingReason(for capability: CapabilityPayload, version: SingboxVersion?) -> String? {
        let minimumVersion = capability.rule.legacyMin.flatMap(SingboxVersion.init)
        let removedAt = capability.rule.removedAt.flatMap(SingboxVersion.init)

        if minimumVersion != nil || removedAt != nil {
            guard let version else {
                return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Cannot identify current sing-box version, unable to determine version bounds. \(capability.rule.note)"
            }
            if let removedAt, version >= removedAt {
                return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Current version \(version.description) falls within the declared restricted range (>= \(removedAt.description)). \(capability.rule.note)"
            }
            if let minimumVersion, version < minimumVersion {
                return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Requires version >= \(minimumVersion.description). \(capability.rule.note)"
            }
        }

        switch capability.rule.type {
        case .supported, .legacy, .compatibility:
            return nil
        case .unsupported:
            return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Current status is unsupported; cannot serve as a safe auto-fallback target. \(capability.rule.note)"
        case .removed:
            return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Current status is removed; cannot serve as a safe auto-fallback target. \(capability.rule.note)"
        case .pendingReview:
            return "Sing-Box [\(capability.kind.rawValue)] \(capability.displayName): Current status is pendingReview; missing sufficient evidence to verify auto-fallback safety. \(capability.rule.note)"
        }
    }

    private static func outboundRequirement(for protocol: V2rayProtocolOutbound) -> RequiredCapability? {
        switch `protocol` {
        case .freedom:
            return RequiredCapability(key: "outbound.freedom", displayName: "Direct outbound", kind: .outboundProtocol)
        case .blackhole:
            return RequiredCapability(key: "outbound.blackhole", displayName: "Block outbound", kind: .outboundProtocol)
        case .dns:
            return RequiredCapability(key: "outbound.dns", displayName: "DNS outbound", kind: .outboundProtocol)
        case .http:
            return RequiredCapability(key: "outbound.http", displayName: "HTTP outbound", kind: .outboundProtocol)
        case .socks:
            return RequiredCapability(key: "outbound.socks", displayName: "SOCKS outbound", kind: .outboundProtocol)
        case .shadowsocks:
            return RequiredCapability(key: "outbound.shadowsocks", displayName: "Shadowsocks outbound", kind: .outboundProtocol)
        case .vmess:
            return RequiredCapability(key: "outbound.vmess", displayName: "VMess outbound", kind: .outboundProtocol)
        case .vless:
            return RequiredCapability(key: "outbound.vless", displayName: "VLESS outbound", kind: .outboundProtocol)
        case .trojan:
            return RequiredCapability(key: "outbound.trojan", displayName: "Trojan outbound", kind: .outboundProtocol)
        case .hysteria2:
            return RequiredCapability(key: "outbound.hysteria2", displayName: "Hysteria2 outbound", kind: .outboundProtocol)
        case .anytls:
            return RequiredCapability(key: "outbound.anytls", displayName: "AnyTLS outbound", kind: .outboundProtocol)
        case .naive:
            return RequiredCapability(key: "outbound.naive", displayName: "Naive outbound", kind: .outboundProtocol)
        case .ssh:
            return RequiredCapability(key: "outbound.ssh", displayName: "SSH outbound", kind: .outboundProtocol)
        }
    }

    private static func transportRequirement(for network: V2rayStreamNetwork) -> RequiredCapability? {
        switch network {
        case .tcp:
            return RequiredCapability(key: "transport.tcpAlias", displayName: "TCP transport", kind: .transportMethod)
        case .kcp:
            return RequiredCapability(key: "transport.kcp", displayName: "KCP transport", kind: .transportMethod)
        case .quic:
            return RequiredCapability(key: "transport.quic", displayName: "QUIC transport", kind: .transportMethod)
        case .domainsocket:
            return RequiredCapability(key: "transport.domainsocket", displayName: "Domain Socket transport", kind: .transportMethod)
        case .ws:
            return RequiredCapability(key: "transport.websocket", displayName: "WebSocket transport", kind: .transportMethod)
        case .h2:
            return RequiredCapability(key: "transport.h2", displayName: "HTTP transport", kind: .transportMethod)
        case .grpc:
            return RequiredCapability(key: "transport.grpc", displayName: "gRPC transport", kind: .transportMethod)
        case .xhttp:
            return RequiredCapability(key: "transport.xhttp", displayName: "XHTTP transport", kind: .transportMethod)
        case .hysteria2:
            return RequiredCapability(key: "transport.hysteria2", displayName: "Hysteria2 transport", kind: .transportMethod)
        }
    }

    private static func securityRequirement(for security: V2rayStreamSecurity) -> RequiredCapability? {
        switch security {
        case .none:
            return RequiredCapability(key: "security.none", displayName: "No extra transport security", kind: .transportSecurity)
        case .tls:
            return RequiredCapability(key: "security.tls", displayName: "TLS", kind: .transportSecurity)
        case .reality:
            return RequiredCapability(key: "security.reality", displayName: "REALITY", kind: .transportSecurity)
        case .xtls:
            return RequiredCapability(key: "security.xtls", displayName: "XTLS", kind: .transportSecurity)
        }
    }

    private static func flowRequirement(for flow: String) -> RequiredCapability? {
        switch flow {
        case "xtls-rprx-vision":
            return RequiredCapability(key: "flow.xtls-rprx-vision", displayName: "xtls-rprx-vision flow", kind: .flow)
        case "xtls-rprx-vision-udp443":
            return RequiredCapability(key: "flow.xtls-rprx-vision-udp443", displayName: "xtls-rprx-vision-udp443 flow", kind: .flow)
        default:
            return nil
        }
    }

    private static func unique(_ reasons: [String]) -> [String] {
        var seen: Set<String> = []
        return reasons.filter { seen.insert($0).inserted }
    }

    private static func legacyFallbackReasons(for profile: ProfileEntity) -> [String] {
        var reasons: [String] = []

        switch profile.protocol {
        case .http:
            reasons.append("Current node uses HTTP outbound; existing auto-fallback logic cannot translate this equivalently to Sing-Box.")
        case .dns:
            reasons.append("Current node uses DNS outbound; existing auto-fallback logic cannot translate this equivalently to Sing-Box.")
        default:
            break
        }

        switch profile.network {
        case .xhttp:
            reasons.append("Current node uses xhttp transport; there is no equivalent implementation for Sing-Box fallback yet.")
        case .kcp:
            reasons.append("Current node uses KCP transport; Sing-Box does not support KCP and cannot automatically fall back.")
        default:
            break
        }

        if profile.security == .xtls {
            reasons.append("Current node uses XTLS; existing auto-fallback logic has not implemented equivalent Sing-Box configuration translation.")
        }

        if profile.network == .tcp && profile.headerType == .http {
            reasons.append("Current node uses TCP + HTTP disguise; existing auto-fallback logic has not implemented equivalent Sing-Box configuration translation.")
        }

        if profile.protocol == .vmess && profile.alterId > 0 {
            reasons.append("Current node uses VMess with alterId > 0 (legacy MD5 authentication), which is incompatible with Sing-Box; please change alterId to 0 (AEAD mode).")
        }

        return reasons
    }
}

enum XrayCompatibilityResolver {
    private static let capabilityRulesNotice = "Compatibility checks prioritize local capability rule configurations; if unavailable, they fall back to built-in Swift defaults."
    private static let defaultLatestReviewedCalendarVersion = XrayVersion(26, 3, 27)

    static func currentVersion() -> XrayVersion? {
        XrayVersion(getCoreVersion())
    }

    private static func latestReviewedCalendarVersion() -> XrayVersion {
        if let configured = CapabilityRulesLoader.load(core: .xray)?.latestReviewedVersion,
           let version = XrayVersion(configured),
           version.isCalendarStyle {
            return version
        }
        return defaultLatestReviewedCalendarVersion
    }

    private static func forwardCompatibilityNotice(for version: XrayVersion?) -> String? {
        let latestReviewedCalendarVersion = latestReviewedCalendarVersion()
        guard let version, version.isCalendarStyle, version > latestReviewedCalendarVersion else {
            return nil
        }
        return "Current Xray-core version \(version.description) is higher than the latest reviewed capability rules version \(latestReviewedCalendarVersion.description). The check is still performed using open-interval rules; if upstream introduces changes in the future, capability rules will need to be updated."
    }

    static func fullSupportList() -> [XrayCapabilityDefinition] {
        XraySupportCatalog.allCapabilities()
    }

    static func decision(for profile: ProfileEntity) -> XrayCoreCompatibilityDecision {
        switch profile.resolvedCoreSelection {
        case .auto:
            return automaticDecision(for: profile)
        case .xray:
            return xrayDecision(for: profile)
        case .singbox:
            return singboxDecision(for: profile)
        }
    }

    private static func automaticDecision(for profile: ProfileEntity) -> XrayCoreCompatibilityDecision {
        let version = currentVersion()
        let shortVersion = getCoreShortVersion()
        let forwardNotice = forwardCompatibilityNotice(for: version)
        let issues = xrayIssues(for: profile, version: version)

        if issues.isEmpty {
            return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: nil, issues: [], canLaunch: true)
        }

        let blockingIssues = issues.filter(\.isBlocking)
        let issueText = issues.map(\.message).joined(separator: "\n")
        let futureVersionText = forwardNotice.map { "\n\n\($0)" } ?? ""

        if blockingIssues.isEmpty {
            // 无非阻塞问题：检查 sing-box 是否能接管；能则静默切换，否则继续用 xray 并提示
            let fallbackReasons = SingboxFallbackCompatibility.incompatibilityReasons(for: profile)
            if fallbackReasons.isEmpty {
                return singboxFallbackDecision(for: profile, issues: issues)
            }
            let warningMessage = "The current node has the following compatibility notices with the installed Xray-core \(shortVersion):\n\n\(issueText)\n\nStartup will continue using Xray-core.\n\n\(capabilityRulesNotice)\(futureVersionText)"
            return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: warningMessage, issues: issues, canLaunch: true)
        }

        let fallbackReasons = SingboxFallbackCompatibility.incompatibilityReasons(for: profile)
        if !fallbackReasons.isEmpty {
            let fallbackText = fallbackReasons.map { "• [Fallback Restricted] \($0)" }.joined(separator: "\n")
            let warningMessage = "The current node has the following incompatibilities with the installed Xray-core \(shortVersion):\n\n\(issueText)\n\nAdditionally, the current node cannot automatically fall back to Sing-Box:\n\n\(fallbackText)\n\nPlease upgrade Xray-core or adjust node configurations and try again.\n\n\(capabilityRulesNotice)\(futureVersionText)"
            return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: warningMessage, issues: issues, canLaunch: false)
        }

        return singboxFallbackDecision(for: profile, issues: issues)
    }

    private static func singboxFallbackDecision(for profile: ProfileEntity, issues: [XrayCompatibilityIssue]) -> XrayCoreCompatibilityDecision {
        var warningMessage: String?
        if profile.protocol == .vmess && profile.alterId > 0 {
            warningMessage = "VMess alterId > 0 (legacy MD5 authentication) is incompatible with sing-box; please change alterId to 0 (AEAD mode)"
        }
        return XrayCoreCompatibilityDecision(coreType: .SingBox, warningMessage: warningMessage, issues: issues, canLaunch: true)
    }

    private static func xrayDecision(for profile: ProfileEntity) -> XrayCoreCompatibilityDecision {
        let version = currentVersion()
        let shortVersion = getCoreShortVersion()
        let forwardNotice = forwardCompatibilityNotice(for: version)
        let issues = xrayIssues(for: profile, version: version)

        guard !issues.isEmpty else {
            return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: nil, issues: [], canLaunch: true)
        }

        let issueText = issues.map(\.message).joined(separator: "\n")
        let futureVersionText = forwardNotice.map { "\n\n\($0)" } ?? ""
        let blockingIssues = issues.filter(\.isBlocking)

        if blockingIssues.isEmpty {
            let warningMessage = "The current node is configured to manually use Xray-core; there are compatibility notices with the installed Xray-core \(shortVersion):\n\n\(issueText)\n\nStartup will continue using Xray-core.\n\n\(capabilityRulesNotice)\(futureVersionText)"
            return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: warningMessage, issues: issues, canLaunch: true)
        }

        let warningMessage = "The current node is configured to manually use Xray-core, but there are incompatibilities with the installed Xray-core \(shortVersion):\n\n\(issueText)\n\nPlease switch to Auto/Sing-Box, upgrade Xray-core, or adjust node configurations and try again.\n\n\(capabilityRulesNotice)\(futureVersionText)"
        return XrayCoreCompatibilityDecision(coreType: .XrayCore, warningMessage: warningMessage, issues: issues, canLaunch: false)
    }

    private static func singboxDecision(for profile: ProfileEntity) -> XrayCoreCompatibilityDecision {
        let fallbackReasons = SingboxFallbackCompatibility.incompatibilityReasons(for: profile)
        guard fallbackReasons.isEmpty else {
            let fallbackText = fallbackReasons.map { "• [Incompatible] \($0)" }.joined(separator: "\n")
            let warningMessage = "The current node is configured to manually use Sing-Box, but incompatibilities were detected according to the capability rules:\n\n\(fallbackText)\n\nPlease switch to Auto/Xray, update Sing-Box capability rules, or adjust node configurations and try again.\n\n\(capabilityRulesNotice)"
            return XrayCoreCompatibilityDecision(coreType: .SingBox, warningMessage: warningMessage, issues: [], canLaunch: false)
        }

        return XrayCoreCompatibilityDecision(coreType: .SingBox, warningMessage: nil, issues: [], canLaunch: true)
    }

    private static func xrayIssues(for profile: ProfileEntity, version: XrayVersion?) -> [XrayCompatibilityIssue] {
        var issues: [XrayCompatibilityIssue] = []

        if let definition = XraySupportCatalog.definition(forOutbound: profile.protocol),
           let issue = XraySupportCatalog.evaluate(definition: definition, version: version) {
            issues.append(issue)
        }

        if let definition = XraySupportCatalog.definition(forTransport: profile.network),
           let issue = XraySupportCatalog.evaluate(definition: definition, version: version) {
            issues.append(issue)
        }


        if let definition = XraySupportCatalog.definition(forSecurity: profile.security),
           let issue = XraySupportCatalog.evaluate(definition: definition, version: version) {
            issues.append(issue)
        }

        if !profile.flow.isEmpty,
           let definition = XraySupportCatalog.definition(forFlow: profile.flow),
           let issue = XraySupportCatalog.evaluate(definition: definition, version: version) {
            issues.append(issue)
        }

        // Shadowsocks in Xray-core does not support TLS/REALITY/XTLS transport security
        if profile.protocol == .shadowsocks, profile.security != .none {
            if let definition = XraySupportCatalog.definition(forSecurity: profile.security) {
                issues.append(XrayCompatibilityIssue(
                    capability: definition,
                    availability: .unsupported(reason: "Shadowsocks in Xray-core does not support \(definition.displayName) transport security (TLS/REALITY are only applicable to protocols like VMess/VLESS/Trojan), falling back to Sing-Box.")
                ))
            }
        }

        if let issue = allowInsecureIssue(for: profile, version: version) {
            issues.append(issue)
        }

        return issues
    }

    // allowInsecure 在 Xray-core 26.1.31 被移除。新核心下：
    // - 已自动获取到 pinnedPeerCertSha256 的普通 TLS 节点 -> 可继续用 Xray（无 issue）。
    // - Hysteria2 -> 无法用 TCP tls ping 取证书，且 Xray hy2 自签 + pinnedPeerCertSha256 失效(#5655)，强制回退 Sing-Box。
    // - 其余未能取到指纹的节点 -> 阻塞，交由自动回退到 Sing-Box（sing-box 仍支持 insecure）。
    private static func allowInsecureIssue(for profile: ProfileEntity, version: XrayVersion?) -> XrayCompatibilityIssue? {
        guard profile.security == .tls, profile.allowInsecure else { return nil }
        // 仅 >= 26.1.31 的核心受影响；旧核心仍支持 allowInsecure。版本未知时按现代核心处理。
        if let version, version < xrayAllowInsecureRemovedVersion { return nil }
        guard let definition = XraySupportCatalog.capability(forKey: "security.tls.allowInsecure") else { return nil }
        let versionText = version?.description ?? "(unknown version)"

        if profile.protocol == .hysteria2 {
            return XrayCompatibilityIssue(capability: definition, availability: .unsupported(
                reason: "Hysteria2 in Xray-core \(versionText) cannot use allowInsecure to bypass certificate validation (removed in 26.1.31), certificate pinning is unavailable, and Xray hy2 self-signing + pinnedPeerCertSha256 is currently broken (#5655); falling back to Sing-Box."))
        }

        let hasPin = !profile.pinnedPeerCertSha256.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        if hasPin { return nil }

        return XrayCompatibilityIssue(capability: definition, availability: .unsupported(
            reason: "allowInsecure has been removed in Xray-core 26.1.31; failed to automatically retrieve the server certificate fingerprint (pinnedPeerCertSha256). Falling back to Sing-Box. Please verify the node is reachable and ping again to retrieve the fingerprint."))
    }
}

extension ProfileEntity {
    var resolvedCoreSelection: ProfileCoreSelection {
        if let coreType, coreType != .auto {
            return coreType
        }
        return CoreSelectionDefaults.selection(for: self.protocol)
    }

    func resolveCoreCompatibility() -> XrayCoreCompatibilityDecision {
        XrayCompatibilityResolver.decision(for: self)
    }
}
