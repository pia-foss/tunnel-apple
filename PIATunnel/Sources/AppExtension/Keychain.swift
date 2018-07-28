//
//  Keychain.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/12/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

/// :nodoc:
public enum KeychainError: Error {
    case add
    
    case notFound
    
    case typeMismatch
}

/// :nodoc:
public class Keychain {
    private let service: String?

    private let accessGroup: String?

    public init() {
        service = Bundle.main.bundleIdentifier
        accessGroup = nil
    }

    public init(group: String) {
        service = nil
        accessGroup = group
    }
    
    public init(team: String, group: String) {
        service = nil
        accessGroup = "\(team).\(group)"
    }
    
    // MARK: Password
    
    public func set(password: String, for username: String, label: String? = nil) throws {
        do {
            let currentPassword = try self.password(for: username)
            guard password != currentPassword else {
                return
            }
        } catch {
            // no pre-existing password
        }

        removePassword(for: username)
        
        var query = [String: Any]()
        setScope(query: &query)
        query[kSecClass as String] = kSecClassGenericPassword
        if let label = label {
            query[kSecAttrLabel as String] = label
        }
        query[kSecAttrAccount as String] = username
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        query[kSecValueData as String] = password.data(using: .utf8)
    
        let status = SecItemAdd(query as CFDictionary, nil)
        guard (status == errSecSuccess) else {
            throw KeychainError.add
        }
    }
    
    @discardableResult public func removePassword(for username: String) -> Bool {
        var query = [String: Any]()
        setScope(query: &query)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        
        let status = SecItemDelete(query as CFDictionary)
        return (status == errSecSuccess)
    }

    public func password(for username: String) throws -> String {
        var query = [String: Any]()
        setScope(query: &query)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard (status == errSecSuccess) else {
            throw KeychainError.notFound
        }
        guard let data = result as? Data else {
            throw KeychainError.notFound
        }
        guard let password = String(data: data, encoding: .utf8) else {
            throw KeychainError.notFound
        }
        return password
    }

    public func passwordReference(for username: String) throws -> Data {
        var query = [String: Any]()
        setScope(query: &query)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnPersistentRef as String] = true
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard (status == errSecSuccess) else {
            throw KeychainError.notFound
        }
        guard let data = result as? Data else {
            throw KeychainError.notFound
        }
        return data
    }
    
    public static func password(for username: String, reference: Data) throws -> String {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        query[kSecMatchItemList as String] = [reference]
        query[kSecReturnData as String] = true
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard (status == errSecSuccess) else {
            throw KeychainError.notFound
        }
        guard let data = result as? Data else {
            throw KeychainError.notFound
        }
        guard let password = String(data: data, encoding: .utf8) else {
            throw KeychainError.notFound
        }
        return password
    }
    
    // MARK: Key
    
    // https://forums.developer.apple.com/thread/13748
    
    public func add(publicKeyWithIdentifier identifier: String, data: Data) throws -> SecKey {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        query[kSecValueData as String] = data

        // XXX
        query.removeValue(forKey: kSecAttrService as String)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard (status == errSecSuccess) else {
            throw KeychainError.add
        }
        return try publicKey(withIdentifier: identifier)
    }
    
    public func publicKey(withIdentifier identifier: String) throws -> SecKey {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        query[kSecReturnRef as String] = true

        // XXX
        query.removeValue(forKey: kSecAttrService as String)

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard (status == errSecSuccess) else {
            throw KeychainError.notFound
        }
//        guard let key = result as? SecKey else {
//            throw KeychainError.typeMismatch
//        }
//        return key
        return result as! SecKey
    }
    
    @discardableResult public func remove(publicKeyWithIdentifier identifier: String) -> Bool {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic

        // XXX
        query.removeValue(forKey: kSecAttrService as String)

        let status = SecItemDelete(query as CFDictionary)
        return (status == errSecSuccess)
    }
    
    // MARK: Helpers
    
    private func setScope(query: inout [String: Any]) {
        if let service = service {
            query[kSecAttrService as String] = service
        } else if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        } else {
            fatalError("No service nor accessGroup set")
        }
    }
}
