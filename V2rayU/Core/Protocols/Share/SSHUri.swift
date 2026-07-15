//
//  SSHUri.swift
//  V2rayU
//
//  Created by yanue on 2026/7/15.
//  Copyright © 2026 yanue. All rights reserved.
//

import Foundation

class SSHUri: BaseShareUri {
    private var profile: ProfileEntity

    // 初始化
    init() {
        profile = ProfileEntity(protocol: .ssh)
    }

    // 从 ProfileEntity 初始化
    required init(from model: ProfileEntity) {
        profile = model
    }

    func getProfile() -> ProfileEntity {
        return profile
    }

    // ssh://user:password@host:port?private_key=base64&private_key_passphrase=passphrase#remark
    func encode() -> String {
        var uri = URLComponents()
        uri.scheme = "ssh"
        uri.user = profile.host.isEmpty ? "root" : profile.host // ssh username is stored in host
        uri.password = profile.password.isEmpty ? nil : profile.password
        uri.host = profile.address
        uri.port = profile.port > 0 ? profile.port : 22

        let sshConfig = profile.getSSHConfig()
        var queryItems: [URLQueryItem] = []

        if !sshConfig.privateKey.isEmpty {
            if let data = sshConfig.privateKey.data(using: .utf8) {
                let base64Key = data.base64EncodedString()
                queryItems.append(URLQueryItem(name: "private_key", value: base64Key))
            }
        }
        if !sshConfig.privateKeyPassphrase.isEmpty {
            queryItems.append(URLQueryItem(name: "private_key_passphrase", value: sshConfig.privateKeyPassphrase))
        }

        if !queryItems.isEmpty {
            uri.queryItems = queryItems
        }

        return (uri.url?.absoluteString ?? "") + "#" + profile.remark.urlEncoded()
    }

    func parse(url: URL) -> Error? {
        guard let host = url.host else {
            return NSError(domain: "SSHUriError", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Missing host"])
        }

        profile.protocol = .ssh
        profile.address = host
        profile.port = url.port ?? 22
        profile.host = url.user ?? "root" // username maps to host
        profile.password = url.password ?? ""

        var sshConfig = ProfileEntity.SSHConfig()
        let query = url.queryParams()

        let pkParam = query.getString(forKey: "private_key", defaultValue: "")
        if !pkParam.isEmpty {
            if let data = Data(base64Encoded: pkParam),
               let decodedKey = String(data: data, encoding: .utf8) {
                sshConfig.privateKey = decodedKey
            } else {
                sshConfig.privateKey = pkParam
            }
        }
        sshConfig.privateKeyPassphrase = query.getString(forKey: "private_key_passphrase", defaultValue: "")
        profile.setSSHConfig(sshConfig)

        if let fragment = url.fragment, !fragment.isEmpty {
            profile.remark = fragment.urlDecoded()
        }
        if profile.remark.isEmpty {
            profile.remark = "\(host):\(profile.port)"
        }

        return nil
    }
}
