//
//  SSHConfig.swift
//  V2rayU
//
//  Created by yanue on 2026/7/15.
//  Copyright © 2026 yanue. All rights reserved.
//

import Foundation

extension ProfileModel {
    var sshPrivateKey: String {
        get { getSSHConfig().privateKey }
        set { setSSHConfigField(\.privateKey, newValue) }
    }

    var sshPrivateKeyPassphrase: String {
        get { getSSHConfig().privateKeyPassphrase }
        set { setSSHConfigField(\.privateKeyPassphrase, newValue) }
    }

    func getSSHConfig() -> ProfileEntity.SSHConfig {
        guard let data = entity.extra.data(using: .utf8),
              let config = try? JSONDecoder().decode(ProfileEntity.SSHConfig.self, from: data) else {
            return ProfileEntity.SSHConfig()
        }
        return config
    }

    func setSSHConfig(_ config: ProfileEntity.SSHConfig) {
        guard let data = try? JSONEncoder().encode(config),
              let jsonString = String(data: data, encoding: .utf8) else { return }
        entity.extra = jsonString
        objectWillChange.send()
    }

    private func setSSHConfigField<T>(_ keyPath: WritableKeyPath<ProfileEntity.SSHConfig, T>, _ value: T) {
        var config = getSSHConfig()
        config[keyPath: keyPath] = value
        setSSHConfig(config)
    }
}
